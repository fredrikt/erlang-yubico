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
%% Types
%%--------------------------------------------------------------------

-type yubico_server_error_response() :: 'backend_error' | 'bad_otp' | 'bad_signature' | 'missing_parameter' | 'no_status_in_response' | 'no_such_client' | 'not_enough_answers' | 'operation_not_allowed' | 'replayed_otp' | 'replayed_request'.

-type bad_auth_code() :: yubico_server_error_response() | 'not_authentic_response' | 'unknown_result'.

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
	  ) -> {'auth','ok'} | {'bad_auth', bad_auth_code()} | {'error', Reason :: any()}.
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
    Request = get_request_url(OTP, Id, APIkey, Nonce, Options),

    HttpClientMod = get_http_client(Options),

    Master = self(),

    %% Set up a timeout for this process
    erlang:send_after(Timeout * 1000, self(), master_timeout),

    Worker = fun(Server) ->
		     spawn_link(fun() ->
					worker_init(Master,
						    HttpClientMod,
						    Nonce,
						    OTP,
						    APIkey,
						    Scheme,
						    Server,
						    WSURL,
						    Request,
						    Timeout,
						    Options,
						    LogFun)
				end)
	     end,
    Workers = [Worker(Server) || Server <- Servers],

    yubico_log:log(LogFun, debug, "I'm coordinating responses to caller ~p from ~p ~p workers : ~p",
		   [Parent, length(Workers), Scheme, Workers]),

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

-spec worker_init(Master :: pid(),
		  HttpClientMod :: atom(),
		  Nonce :: nonempty_string(),
		  OTP :: nonempty_string(),
		  APIkey :: yubico:apikey(),
		  Scheme :: yubico_client_scheme(),
		  Server :: nonempty_string(),
		  WSURL :: nonempty_string(),
		  Request :: nonempty_string(),
		  Timeout :: non_neg_integer(),
		  Options :: yubico:yubico_client_options(),
		  LogFun :: yubico_log:logfun()
		 ) -> ok.
worker_init(Master, HttpClientMod, Nonce, OTP, APIkey, Scheme, Server, WSURL, Request, Timeout, Options, LogFun) ->
    SchemeStr =
	case Scheme of
	    http  -> "http://";
	    https -> "https://"
	end,

    URL = SchemeStr ++ Server ++ WSURL ++ Request,

    Res =
	case HttpClientMod:verify(URL, Timeout, Options, LogFun) of
	    {ok, Body} ->
		check_response(OTP, APIkey, Nonce, Body, Server, LogFun);
	    {error, Reason} ->
		{error, Reason}
	end,
    %% This workers job is done. Tell the master process what reponse we got and terminate.
    Master ! {worker_response, self(), Res},
    ok.

-spec get_request_url(OTP :: nonempty_string(),
		      Id :: nonempty_string(),
		      APIkey :: yubico:apikey(),
		      Nonce :: nonempty_string(),
		      Options :: yubico:yubico_client_options()
		     ) -> nonempty_string().
get_request_url(OTP, Id, APIkey, Nonce, Options) ->
    SignRequest = get_sign_request(Options),

    %% Parameters in Validation Protocol Version 2.0
    ReqTimestamp = get_req_timestamp(Options),
    ReqSyncLevel = get_req_synclevel(Options),
    ReqTimeout = get_req_timeout(Options),

    NoEmpty = [ReqTimestamp, ReqSyncLevel, ReqTimeout] -- [[]],

    %% The mandatory parameters
    L1 = ["otp=" ++ OTP,
	  "id=" ++ Id,
	  "nonce=" ++ Nonce
	 ] ++ NoEmpty,
    L2 = lists:sort(L1),	%% sorting required for signing
    L3 = sign_request(L2, APIkey, SignRequest),
    Str = string:join(L3, "&"),
    lists:flatten(Str).

-spec sign_request(In :: [nonempty_string()],
		   APIkey :: yubico:apikey(),
		   SignRequest :: boolean()
		  ) -> [nonempty_string()].
sign_request(In, APIkey, true) ->
    H = get_sha1_hmac(APIkey, In),
    In ++ ["h=" ++ H];
sign_request(In, _APIkey, false) ->
    In.

-spec check_response(OTP :: nonempty_string(),
		     APIkey :: yubico:apikey(),
		     Nonce :: nonempty_string(),
		     Body :: dict(),
		     Server :: nonempty_string(),
		     LogFun :: yubico_log:logfun()
		    ) -> {'auth','ok'} | {'bad_auth', bad_auth_code()}.
check_response(OTP, APIkey, Nonce, Body, Server, LogFun) ->
    case verify_authentic_response(OTP, APIkey, Nonce, Body, LogFun) of
	true ->
	    case get_verification_status (Body) of
		ok ->
		    {auth, ok};
		Other ->
		    yubico_log:log(LogFun, normal, "Verification of OTP ~p with server ~p FAILED : ~p",
				   [OTP, Server, Other]),
		    {bad_auth, Other}
	    end;
	Reason ->
	    yubico_log:log(LogFun, normal, "Verification of OTP ~p with server ~p "
			   "FAILED AUTHENTICITY CHECK (~p) :~n~p", [OTP, Server, Reason, dict:to_list(Body)]),
	    {bad_auth, not_authentic_response}
    end.

-spec verify_authentic_response(OTP :: nonempty_string(),
				APIkey :: yubico:apikey(),
				Nonce :: nonempty_string(),
				Body :: dict(),
				LogFun :: yubico_log:logfun()
			       ) -> 'true' | 'bad_otp_or_nonce' | 'failed_hmac_verification'.
verify_authentic_response(OTP, APIkey, Nonce, Body, LogFun) ->
    case dict_has("otp", OTP, Body) andalso
	dict_has("nonce", Nonce, Body) of
	true ->
	    %% 'h' is the hmac, so it must be removed before we generate a hmac of the rest
	    Body2 = dict:erase("h", Body),
	    Params = lists:sort(dict:to_list(Body2)),
	    %% Make key=value strings
	    Data1 = [lists:concat([H, "=", V]) || {H, V} <- Params],
	    Data2 = string:join(Data1, "&"),
	    HMAC = get_sha1_hmac(APIkey, Data2),

	    case dict_has("h", HMAC, Body) of
		true ->
		    true;
		false ->
		    yubico_log:log(LogFun, debug, "Calculated non-matching HMAC ~p from :~n~s",
				   [HMAC, Data2]),
		    failed_hmac_verification
	    end;
	false ->
	    bad_otp_or_nonce
    end.

-spec dict_has(Key :: nonempty_string(),
	       Val :: nonempty_string(),
	       Dict :: dict()) -> boolean().
dict_has(Key, Val, Dict) ->
    case dict:find(Key, Dict) of
	{ok, Val} ->
	    true;
	_ ->
	    false
    end.

-spec get_sha1_hmac(Key :: yubico:apikey(),
		    Data :: iolist()
		   ) -> string().
get_sha1_hmac(Key, Data) ->
    MAC = crypto:sha_mac(Key, Data),
    base64:encode_to_string(MAC).

-spec get_verification_status(Body :: dict()
			     ) -> 'ok' | yubico_server_error_response() | 'unknown_result'.
get_verification_status(Body) ->
    %% Don't do list_to_atom to not depleat finite atom table
    case dict:find("status", Body) of
	{ok, Value} ->
	    case string:to_upper(Value) of
		"OK"			-> ok;
		"BAD_OTP"		-> bad_otp;
		"REPLAYED_OTP"		-> replayed_otp;
		"BAD_SIGNATURE"		-> bad_signature;
		"MISSING_PARAMETER"	-> missing_parameter;
		"NO_SUCH_CLIENT"	-> no_such_client;
		"OPERATION_NOT_ALLOWED"	-> operation_not_allowed;
		"BACKEND_ERROR"		-> backend_error;
		"NOT_ENOUGH_ANSWERS"	-> not_enough_answers;
		"REPLAYED_REQUEST"	-> replayed_request;
		_Other			-> unknown_result
	    end;
	error ->
	    no_status_in_response
    end.

-spec get_sign_request(Options :: yubico:yubico_client_options()
		      ) -> boolean().
get_sign_request(Options) ->
    case lists:keysearch(sign_request, 1, Options) of
	{value, {sign_request, Bool}} when is_boolean(Bool) ->
	    Bool;
	false ->
	    %% Default is to sign the requests
	    true
    end.


-spec get_nonce(Options :: yubico:yubico_client_options()
	       ) -> string().
get_nonce(Options) ->
    case lists:keysearch(req_nonce, 1, Options) of
	{value, {req_nonce, L}} when is_list(L) ->
	    if
		length(L) < 16 ->
		    erlang:error(nonce_too_short);
		length(L) > 40 ->
		    erlang:error(nonce_too_long);
		true ->
		    lists:flatten(L)
	    end;
	false ->
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
	    lists:flatten(Hex)
    end.

-spec get_req_timestamp(Options :: yubico:yubico_client_options()
		       ) -> string().
get_req_timestamp(Options) ->
    case lists:keysearch(req_timestamp, 1, Options) of
	{value, {req_timestamp, true}} ->
	    "timestamp=1";
	false ->
	    %% Default is to not request timestamp and session counter information
	    %% in the response
	    []
    end.

-spec get_req_synclevel(Options :: yubico:yubico_client_options()
		       ) -> string().
get_req_synclevel(Options) ->
    case lists:keysearch(req_synclevel, 1, Options) of
	{value, {req_synclevel, Int}} when is_integer(Int) ->
	    lists:concat(["sl=", Int]);
	{value, {req_synclevel, 'fast'}} ->
	    "sl=fast";
	{value, {req_synclevel, 'secure'}} ->
	    "sl=secure";
	false ->
	    %% Default is the server defined level 'secure'
	    %"sl=secure"
	    []
    end.

-spec get_req_timeout(Options :: yubico:yubico_client_options()
		     ) -> string().
get_req_timeout(Options) ->
    case lists:keysearch(req_timeout, 1, Options) of
	{value, {req_timeout, Int}} when is_integer(Int) ->
	    lists:concat(["timeout=", Int]);
	false ->
	    %% Default is to let the server decide the sync responses timeout
	    []
    end.

-spec get_http_client(Options :: yubico:yubico_client_options()
		     ) -> atom().
get_http_client(Options) ->
    case lists:keysearch(http_client, 1, Options) of
	{value, {http_client, Module}} when is_atom(Module) ->
	    Module;
	false ->
	    %% Default is the bundled module using Erlang/OTP inets http client
	    yubico_http_client
    end.
