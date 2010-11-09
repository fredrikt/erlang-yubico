%%%-------------------------------------------------------------------
%%% File    : yubico_http_client.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      Backend module to make HTTP querys to Yubico servers.
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
	 verify/4
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

%%====================================================================
%% Internal functions
%%====================================================================

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
