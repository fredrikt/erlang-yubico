%%%-------------------------------------------------------------------
%%% File    : yubico_http_client.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      Backend module to make HTTP querys to Yubico servers.
%%%
%%%           'verify' backend functions should export a
%%%           spawn_link_verify/4 function that starts a worker
%%%           process preforming the actual verification call. That
%%%           process should report it's result with a message
%%%
%%%              {worker_response, self(), {ok, Dict :: dict()} |
%%%                                        {error, Reason :: any()}
%%%              }
%%%
%%%           to the process that invoked spawn_link_verify/4.
%%%
%%% @since    7 Nov 2010 by Fredrik Thulin <fredrik@thulin.net>
%%% @end
%%%
%%% Copyright (c) 2010, Fredrik Thulin <fredrik@thulin.net>
%%% See the file LICENSE for full license.
%%%
%%%-------------------------------------------------------------------

-module(yubico_http_client).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
	 spawn_link_verify/8
	]).

%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% @doc     Make a call to a 'verify' URL and return the response
%%            In : string()
%%
%%          Returns :
%%
%%            {ok, ParsedBody :: dict()} any key=value pairs from the
%%                                       HTTP response as a dict()
%%            {error, Reason ::any()}
%% @end
%%--------------------------------------------------------------------
-spec spawn_link_verify(Server :: nonempty_string(),
			URL :: string(),
			Timeout :: non_neg_integer(),
			OTP :: nonempty_string(),
			APIkey :: yubico:apikey(),
			Nonce :: nonempty_string(),
			Options :: yubico:yubico_client_options(),
			LogFun :: yubico_log:logfun()
		       ) -> pid().
spawn_link_verify(Server, URL, Timeout, OTP, APIkey, Nonce, Options, LogFun)
 when is_list(Server), is_list(URL), is_integer(Timeout), is_list(OTP), is_binary(APIkey), is_list(Nonce) ->
    Master = self(),
    spawn_link(fun() ->
		       worker_init(Master, Server, URL, Timeout, OTP, APIkey, Nonce, Options, LogFun)
	       end).


%%====================================================================
%% Internal functions
%%====================================================================

-spec worker_init(Master :: pid(),
		  Server :: nonempty_string(),
		  URL :: nonempty_string(),
		  Timeout :: non_neg_integer(),
		  OTP :: nonempty_string(),
		  APIkey :: yubico:apikey(),
		  Nonce :: nonempty_string(),
		  Options :: yubico:yubico_client_options(),
		  LogFun :: yubico_log:logfun()
		 ) -> ok.
worker_init(Master, Server, URL, Timeout, OTP, APIkey, Nonce, Options, LogFun) ->
    Res =
	case verify(URL, Timeout, Options, LogFun) of
	    {ok, Body} ->
		yubico_response:check_verify_response(OTP, APIkey, Nonce, Body, Server, LogFun);
	    {error, Reason} ->
		{error, Reason}
	end,

    %% This workers job is done. Tell the master process what reponse we got and terminate.
    Master ! {worker_response, self(), Res},
    ok.

%%--------------------------------------------------------------------
%% @doc     Make a call to a 'verify' URL and return the response
%%            In : string()
%%
%%          Returns :
%%
%%            {ok, ParsedBody :: dict()} any key=value pairs from the
%%                                       HTTP response as a dict()
%%            {error, Reason ::any()}
%% @end
%%--------------------------------------------------------------------
-spec verify(URL :: string(),
	     Timeout :: non_neg_integer(),
	     Options :: yubico:yubico_client_options(),
	     LogFun :: yubico_log:logfun()
	    ) -> {'error', Reason :: any()} | {'ok', dict()}.
verify(URL, Timeout, _Options, LogFun) when is_list(URL), is_integer(Timeout) ->
    yubico_log:log(LogFun, debug, "yubico_http_client:verify (URL ~p, timeout ~p)", [URL, Timeout]),

    case inets:start() of
	ok ->
	    ok;
	{error, {already_started, inets}} ->
	    ok;
	_ ->
	    erlang:error(inets_not_available)
    end,

    case make_request(URL, Timeout, LogFun) of
	{ok, Response} ->
	    parse_response(Response);
	{error, Reason} ->
	    {error, Reason}
    end.

-spec make_request(URL :: string(),
		   Timeout :: non_neg_integer(),
		   LogFun :: yubico_log:logfun()
		  ) -> {'error',_} | {'ok', Body :: string()}.
make_request(URL, Timeout, LogFun) ->
    case http:request(get, {URL, []}, [{timeout, Timeout * 1000}], []) of
	{ok, {{_HTTPVER, 200, Reason}, _Headers, Body}} ->
	    yubico_log:log(LogFun, debug, "yubico_http_client:verify got response 200 ~s :~n~s", [Reason, Body]),
	    {ok, Body};
	{ok, Response} ->
	    yubico_log:log(LogFun, debug, "yubico_http_client:verify got non-200 response :~n~p", [Response]),
	    {error, unknown_response};
	{error, Reason} ->
	    yubico_log:log(LogFun, normal, "yubico_http_client:verify http:request/4 got error : ~p",
			    [Reason]),
	    {error, Reason}
    end.

-spec parse_response(string()) -> {'ok', dict()}.
parse_response(In) when is_list(In) ->
    Lines = string:tokens(In, "\r\n"),
    Tuples = to_tuples(Lines),
    {ok, dict:from_list(Tuples)}.

-spec to_tuples([nonempty_string()]) -> [{Key :: string(), Val :: string()}].
to_tuples([H | T]) ->
    case string:chr(H, $=) of
	Index when is_integer(Index), Index > 0 ->
	    Key = string:substr(H, 1, Index - 1),
	    Val = string:substr(H, Index + 1),
	    [{Key, Val}] ++ to_tuples(T);
	0 ->
	    %% XXX correct to ignore non- key=value ?
	    to_tuples(T)
    end;
to_tuples([]) ->
    [].
