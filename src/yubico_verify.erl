%%%-------------------------------------------------------------------
%%% File    : yubico_verify.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      This module contains the complete 'verify' web service
%%%           client. The recommended API is NOT in this module (see
%%%           yubico.erl).
%%%
%%%           The 'http' function will perform a web service request
%%%           using plain text http. The response will be verified
%%%           using HMAC SHA1 and your shared secret (APIkey).
%%%
%%%           We support querying n servers in parallell. After all
%%%           arguments are checked and the request is created (and
%%%           signed), we will spawn a 'master' process. The master
%%%           process will spawn a 'worker' process for each entry
%%%           in the list of Servers. The masters job is to wait for
%%%           responses from the workers. It will forward any received
%%%           successful response (status=OK) immediately, but store
%%%           all other responses and use them only if necessary.
%%%
%%%           The master process also provides error isolation for the
%%%           caller. It is spawned using spawn_monitor, and in turn
%%%           spawns all workers with spawn_link. If something goes
%%%           wrong in the master or workers, the caller (your
%%%           program) won't crash but will get a
%%%           {error, yubico_master_process_failed} response.
%%%
%%%           XXX perhaps the master should set the process flag to
%%%           trap exits? If the master is killed by a defect in a
%%%           worker (i.e. a bug in the HTTP client code), all workers
%%%           will be killed, even if one of the others would have
%%%           resulted in a status=OK response.
%%%
%%%           Future extensions should be easy. Options is passed
%%%           through to this module, and passed on to the
%%%           HttpClientMod, which is also made configurable by the
%%%           caller to make it easy to add functionality later, or
%%%           for someone else.
%%%
%%% @since    7 Nov 2010 by Fredrik Thulin <fredrik@thulin.net>
%%% @end
%%%
%%% Copyright (c) 2010, Fredrik Thulin <fredrik@thulin.net>
%%% See the file LICENSE for full license.
%%%
%%%-------------------------------------------------------------------

-module(yubico_verify).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
         http/8
        ]).

%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------
-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type yubico_client_scheme() :: 'http'.

%%--------------------------------------------------------------------
%% Macros
%%--------------------------------------------------------------------
%% XXX spec says nonce is 16..40 bytes, if I make it 40 (20 here,
%% we double length when hex-encoding) I get server failures. Will ask Yubico.
-define(DEFAULT_NONCE_BYTES, 16).

%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% @doc     Perform a 'verify' Yubico web service request.
%%
%%            OTP: the string outputed by your YubiKey (without
%%            the ending "\n").
%%
%%            Id: a string with your API key Id (e.g. "87").
%%
%%            APIkey: either your API key as a binary, or in the
%%            base64-encoded format Yubico supplies it in.
%%
%%            Servers: a list of server names as strings.
%%
%%            WSURL: Where on the Servers the 'verify' WS is located.
%%
%%            Timeout: Timeout in seconds.
%%
%%            Options: List of {Key, Value} options. See module
%%                     'yubico' documentation for details.
%%
%%          Returns :
%%
%%            ok
%% @end
%%--------------------------------------------------------------------
-spec http(OTP :: nonempty_string(),
	   Id :: nonempty_string(),
	   APIkey :: yubico:apikey(),
	   Servers :: [nonempty_string()],
	   WSURL :: nonempty_string(),
	   Timeout :: non_neg_integer(),
	   Options :: yubico:yubico_client_options(),
	   LogFun :: yubico_log:logfun()
	  ) -> {'auth','ok'} | {'bad_auth', yubico_response:bad_auth_code()} | {'error', Reason :: any()}.
http(OTP, Id, APIkey, Servers, WSURL, Timeout, Options, LogFun)
  when is_list(OTP), is_list(Id), is_binary(APIkey), is_list(Servers),
       is_list(WSURL), is_list(Options), is_function(LogFun) ->

    Nonce = get_nonce(Options),

    %% Start a master process that will in turn start a HTTP client
    %% process for every entry in Servers.
    Caller = self(),
    {Master, MRef} =
	spawn_monitor(
	  fun() ->
		  master_init(Caller,
			      Nonce,
			      OTP,
			      Id,
			      APIkey,
			      http,
			      Servers,
			      WSURL,
			      Timeout,
			      Options,
			      LogFun)
	  end
	 ),

    %% wait for first response
    receive
	{master_response, Master, Response} ->
	    Response;
	{'DOWN', MRef, process, Master, _Info} ->
	    %% the controller has exited
	    {error, yubico_master_process_failed}
    after 1000 * Timeout ->
	    {error, timeout}
    end.

-spec master_init(Parent :: pid(),
		  Nonce :: nonempty_string(),
		  OTP :: nonempty_string(),
		  Id :: nonempty_string(),
		  APIkey :: yubico:apikey(),
		  Scheme :: yubico_client_scheme(),
		  Servers :: [nonempty_string()],
		  WSURL :: nonempty_string(),
		  Timeout :: non_neg_integer(),
		  Options :: yubico:yubico_client_options(),
		  LogFun :: yubico_log:logfun()
		 ) -> ok.
master_init(Parent, Nonce, OTP, Id, APIkey, Scheme, Servers, WSURL, Timeout, Options, LogFun) ->
    Request = get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options),
    HttpClientMod = get_http_client(Options),

    SchemeStr =
	case Scheme of
	    http  -> "http://";
	    https -> "https://"
	end,

    StartWorker =
	fun(Server) ->
		URL = SchemeStr ++ Server ++ WSURL ++ Request,

		HttpClientMod:spawn_link_verify(Server,
						URL,
						Timeout,
						OTP,
						APIkey,
						Nonce,
						Options,
						LogFun
					       )
	end,
    Workers = [StartWorker(Server) || Server <- Servers],

    yubico_log:log(LogFun, debug, "I'm coordinating responses to caller ~p from ~p ~p workers :~n~p",
		   [Parent, length(Workers), Scheme, Workers]),

    %% Set up a timeout for this process
    erlang:send_after(Timeout * 1000, self(), master_timeout),

    master_wait_for_responses(Parent, Workers, LogFun).

-spec master_wait_for_responses(Parent :: pid(),
				Workers :: [pid()],
				LogFun :: yubico_log:logfun()
			       ) -> ok.
master_wait_for_responses(Parent, Workers, LogFun) ->
    master_wait_for_responses(Parent, Workers, LogFun, []).

-spec master_wait_for_responses(Parent :: pid(),
                                Workers :: [pid()],
				LogFun :: yubico_log:logfun(),
				Responses :: [any()]
			       ) -> ok.
master_wait_for_responses(Parent, [], LogFun, [FirstResponse | _Rest]) ->
    %% No workers left, return first bad response
    yubico_log:log(LogFun, debug, "We're out of workers, but have only bad responses. "
		   "Sending the first one of them to caller ~p : ~p", [Parent, FirstResponse]),
    Parent ! {master_response, self(), FirstResponse},
    ok;
master_wait_for_responses(Parent, Workers, LogFun, BadResponses) ->
    receive
	master_timeout ->
	    %% Time for us to finish
	    Parent ! {master_response, self(), timeout};
	{worker_response, Worker, {'auth', 'ok'} = Response} ->
	    %% verify the response was from one of our workers
	    T = Workers -- [Worker],
	    if
		T /= Workers ->
		    %% Tell caller about successful response, and then terminate.
		    yubico_log:log(LogFun, debug, "Got successful auth response from ~p, sending "
				   "it to caller ~p", [Worker, Parent]),
		    Parent ! {master_response, self(), Response},
		    ok;
		true ->
		    %% just ignore invalid worker responses
		    yubico_log:log(LogFun, debug, "Ignoring worker_response from pid ~p not in my list", [Worker]),
		    master_wait_for_responses(Parent, Workers, LogFun, BadResponses)
	    end;
	{worker_response, Worker, Response} ->
	    %% Unsucessful response. Store but do not forward until no workers remain.
	    NewWorkers = Workers -- [Worker],
	    yubico_log:log(LogFun, debug, "Non-successful response ~p from worker ~p.~nRemaining workers : ~p",
			   [Response, Worker, NewWorkers]),
	    master_wait_for_responses(Parent, NewWorkers, LogFun, [Response | BadResponses])
    end.


-spec get_request_url(OTP :: nonempty_string(),
		      Id :: nonempty_string(),
		      APIkey :: yubico:apikey(),
		      Nonce :: nonempty_string(),
		      LogFun :: yubico_log:logfun(),
		      Options :: yubico:yubico_client_options()
		     ) -> nonempty_string().
get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options) ->
    SignRequest = get_sign_request(Options),
    ReqTimestamp = get_req_timestamp(Options),
    ReqSyncLevel = get_req_synclevel(Options),
    ReqTimeout = get_req_timeout(Options),

    %% Parameters in Validation Protocol Version 2.0
    Mandatory = [{"otp", OTP},
		 {"id", Id},
		 {"nonce", Nonce}
		],

    Extra = [ReqTimestamp, ReqSyncLevel, ReqTimeout],

    %% For signing, we need a list of the parameters non-escaped
    UnescapedStr = get_param_str(Mandatory ++ Extra, false),
    HMAC = sign_request(UnescapedStr, APIkey, LogFun, SignRequest),

    %% The actual URI needs to be escaped
    EscapedStr = get_param_str(Mandatory ++ Extra ++ HMAC, true),

    lists:flatten(EscapedStr).

-spec get_param_str([{Key :: string(), Value :: string() | 'undefined'}], Escape :: boolean()
		   ) -> string().
get_param_str(In, Escape) ->
    NoEmpty = [X || X <- In, X /= []],
    L1 = get_param_str2(NoEmpty, Escape),
    L2 = lists:sort(L1),	%% required for signing, good for consistency
    string:join(L2, "&").

get_param_str2([{Key, Value} | T], true) when is_list(Value) ->
    [Key ++ "=" ++ edoc_lib:escape_uri(Value)] ++ get_param_str2(T, true);
get_param_str2([{Key, Value} | T], false) when is_list(Value) ->
    [Key ++ "=" ++ Value] ++ get_param_str2(T, false);
get_param_str2([{_Key, undefined} | T], Escape) ->
    get_param_str2(T, Escape);
get_param_str2([], _Escape) ->
    [].

-spec sign_request(In :: [nonempty_string()],
		   APIkey :: yubico:apikey(),
		   LogFun :: yubico_log:logfun(),
		   SignRequest :: boolean()
		  ) -> [{H :: nonempty_string(), HMAC :: nonempty_string()}].
sign_request(In, APIkey, LogFun, true) ->
    HMAC = yubico_util:get_sha1_hmac(APIkey, In, LogFun),
    [{"h", HMAC}];
sign_request(_In, _APIkey, _LogFun, false) ->
    [].


-spec get_sign_request(Options :: yubico:yubico_client_options()
		      ) -> boolean().
get_sign_request(Options) ->
    %% Default is to sign the requests
    Default = true,
    yubico_util:get_option(sign_request, boolean, Default, Options).

-spec get_nonce(Options :: yubico:yubico_client_options()
	       ) -> string().
get_nonce(Options) ->
    Nonce =
	case yubico_util:get_option(req_nonce, list, undefined, Options) of
	    undefined ->
		%% Default is to generate a nonce
		case crypto:start() of
		    ok ->
			ok;
		    {error, {already_started, crypto}} ->
			ok;
		    _ ->
			erlang:error(crypto_not_available)
		end,
		Random = crypto:rand_bytes(?DEFAULT_NONCE_BYTES),
		Hex = yubico_util:to_hex(binary_to_list(Random)),
		lists:flatten(Hex);
	    L ->
		lists:flatten(L)
	end,
    if
	length(Nonce) < 16 ->
	    erlang:error(nonce_too_short);
	length(Nonce) > 40 ->
	    erlang:error(nonce_too_long);
	true ->
	    Nonce
    end.

-spec get_req_timestamp(Options :: yubico:yubico_client_options()
		       ) -> {Key :: string(), Value :: string() | 'undefined'}.
get_req_timestamp(Options) ->
    %% Default is to not request timestamp and session counter information
    %% in the response
    Default = false,
    {"timestamp",
     case yubico_util:get_option(req_timestamp, boolean, Default, Options) of
	 true -> "1";
	 false -> undefined
     end
    }.

-spec get_req_synclevel(Options :: yubico:yubico_client_options()
		       ) -> {Key :: string(), Value :: string() | 'undefined'}.
get_req_synclevel(Options) ->
    %% Default is to let the server decice
    Default = undefined,
    {"sl",
     case yubico_util:get_option(req_synclevel, any, Default, Options) of
	 Int when is_integer(Int) ->
	     integer_to_list(Int);
	 'fast' -> "fast";
	 'secure' -> "secure";
	 Default -> Default
     end
    }.

-spec get_req_timeout(Options :: yubico:yubico_client_options()
		     ) -> {Key :: string(), Value :: string() | 'undefined'}.
get_req_timeout(Options) ->
    %% Default is to let the server decide the sync responses timeout
    Default = undefined,
    {"timeout",
     case yubico_util:get_option(req_timeout, integer, Default, Options) of
	 Default -> Default;
	 L -> integer_to_list(L)
     end
    }.

-spec get_http_client(Options :: yubico:yubico_client_options()
		     ) -> atom().
get_http_client(Options) ->
    %% Default is the bundled module using Erlang/OTP inets http client
    Default = yubico_http_client,
    yubico_util:get_option(http_client, atom, Default, Options).


%%====================================================================
%% EUnit tests
%%====================================================================
-ifdef(EUNIT).

get_options_test_() ->
    Options = [{http_client, 'yubico_test'},
	       {req_synclevel, 'fast'},
	       {sign_request, 'true'}
	      ],
    [
     ?_assert(get_http_client(Options) =:= 'yubico_test'),
     ?_assert(get_req_synclevel(Options) =:= {"sl", "fast"}),
     ?_assertEqual({"timeout", undefined}, get_req_timeout(Options)),
     ?_assert(get_sign_request(Options) =:= 'true'),
     ?_assert(get_sign_request([]) =:= 'true')
    ].


get_nonce_test_() ->
    OptionsLong  = [{req_nonce, lists:seq(1, 80)}],
    OptionsShort = [{req_nonce, lists:seq(1, 8)}],
    Options      = [{req_nonce, lists:seq(1, 18)}],

    [
     ?_assertException(error, nonce_too_long, get_nonce(OptionsLong)),
     ?_assertException(error, nonce_too_short, get_nonce(OptionsShort)),
     ?_assertEqual(lists:seq(1, 18), get_nonce(Options)),
     ?_assertEqual(32, length(get_nonce([])))
    ].

get_param_str_test_() ->
    Params = [{"t1", "foo/bar"},
	      [],
	      {"t2", "test"}
	     ],

    [
     ?_assertEqual("t1=foo/bar&t2=test", get_param_str(Params, false)),
     ?_assertEqual("t1=foo%2fbar&t2=test", get_param_str(Params, true)),
     ?_assertEqual("t1=foo%2fbar&t2=test", get_param_str(Params ++ [{"t3", undefined}], true)),
     ?_assertEqual("t1=foo%2fbar&t2=test", get_param_str(Params ++ [get_req_timeout([])], true))
    ].

get_request_url_test_() ->
    OTP = "abc123",
    Id  = "87",
    APIkey = <<"veryrandom">>,
    Nonce  = "aabbccddeeff",
    Options1 = [{sign_request, true}],
    Options2 = [{sign_request, false}],
    LogFun = yubico_log:fun_quiet(),

    [
     ?_assertEqual("h=7BqT4wsQk1SNgYu1YwtDizl1ciM%3d&id=87&nonce=aabbccddeeff&otp=abc123",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options1)
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2)
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123&timestamp=1",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2 ++ [{req_timestamp, true}])
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123&sl=fast",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2 ++ [{req_synclevel, 'fast'}])
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123&sl=secure",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2 ++ [{req_synclevel, 'secure'}])
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123&sl=90",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2 ++ [{req_synclevel, 90}])
		 ),
     ?_assertEqual("id=87&nonce=aabbccddeeff&otp=abc123&timeout=4711",
		  get_request_url(OTP, Id, APIkey, Nonce, LogFun, Options2 ++ [{req_timeout, 4711}])
		 )
    ].

-endif.
