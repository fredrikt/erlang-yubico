%%%-------------------------------------------------------------------
%%% File    : yubico.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      YubiCloud OTP key verification client.
%%%
%%%           This is the API module to an implementation of the
%%%           Yubico Validation Protocol Version 2.0.
%%%
%%%           That protocol describes two different mechanisms. One
%%%           uses SSL (with certificate validation) to secure the
%%%           communication between client and YubiCloud servers, the
%%%           other one uses plain text communication (over HTTP)
%%%           with HMAC verification of the contents of the exchanged
%%%           packets.
%%%
%%%           The second one is the one implemented this far. This
%%%           means you MUST have an API key to use this module. The
%%%           API key is a shared secret between you and the Yubico
%%%           server(s). If you use the YubiCloud servers (the
%%%           default,currently five servers on three continents) you
%%%           must first get an API key from Yubico. This is done at
%%%           https://upgrade.yubico.com/getapikey/.
%%%
%%%           Valid Options :
%%%
%%%             {logfun, Fun :: fun()}
%%%                 default is a quiet fun
%%%
%%%             {servers, [string()]}
%%%                 default is to query the five YubiCloud servers
%%%
%%% @since    7 Nov 2010 by Fredrik Thulin <fredrik@thulin.net>
%%% @end
%%%
%%% Copyright (c) 2010, Fredrik Thulin <fredrik@thulin.net>
%%% See the file LICENSE for full license.
%%%
%%%-------------------------------------------------------------------

-module(yubico).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
	 simple_verify/4
	]).

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type yubico_client_options() :: [{Key :: atom(), Value :: any()}].
-type apikey() :: binary().

%%--------------------------------------------------------------------
%% Macros
%%--------------------------------------------------------------------
-define(YUBICO_VERIFY_SERVERS, ["api.yubico.com",
				"api2.yubico.com",
				"api3.yubico.com",
				"api4.yubico.com",
				"api5.yubico.com"
			       ]).

-define(YUBICO_VERIFY_WSURL, "/wsapi/2.0/verify?").
-define(DEFAULT_TIMEOUT, 10).


%%====================================================================
%% External functions
%%====================================================================



%%--------------------------------------------------------------------
%% @doc     Perform a 'verify' web service request, using as sensible
%%          defaults as possible.
%%
%%            OTP: the string outputed by your YubiKey (without
%%            the ending "\n").
%%
%%            Id: a string with your API key Id (e.g. "87").
%%
%%            APIkey: either your API key as a binary, or in the
%%            base64-encoded format Yubico supplies it in.
%%
%%            Options: List of {Key, Value} options. See module
%%                     documentation for details.
%%
%%          Returns :
%%
%%            {auth, ok} on successful validation
%%            {bad_auth, Code :: atom()} on failed validation
%%            {error, Reason :: any()} on errors
%% @end
%%--------------------------------------------------------------------
-spec simple_verify(OTP :: nonempty_string(),
		    Id :: nonempty_string(),
		    APIkey :: apikey() | string(),
		    Options :: yubico_client_options()
		   ) -> {'auth', 'ok'} | {'bad_auth', yubico_verify:bad_auth_code()} | {'error', Reason :: any()}.
simple_verify(OTP, Id, APIkey, Options) when is_list(APIkey) ->
    %% string APIkey, assume base64 encoded
    NewAPIkey =
	try base64:decode(APIkey) of
	    Res -> Res
	catch
	    _:_ ->
		erlang:error(bad_api_key)
	end,
    simple_verify(OTP, Id, NewAPIkey, Options);
simple_verify(OTP, Id, APIkey, Options) when is_list(OTP), is_list(Id), is_binary(APIkey), is_list(Options) ->
    LogFun = get_logfun(Options),
    Servers = get_servers(Options),
    Timeout = get_timeout(Options),

    yubico_verify:http(OTP,
		       Id,
		       APIkey,
		       Servers,
		       ?YUBICO_VERIFY_WSURL,
		       Timeout,
		       Options,
		       LogFun
		      ).


%%====================================================================
%% Internal functions
%%====================================================================

-spec get_logfun(Options :: yubico_client_options()
		) -> yubico_log:logfun().
get_logfun(Options) ->
    case lists:keysearch(logfun, 1, Options) of
	{value, {logfun, Fun}} when is_function(Fun) ->
	    Fun;
	false ->
	    %% Default is to not log anything
	    yubico_log:fun_quiet()
    end.

-spec get_servers(Options :: yubico_client_options()
		 ) -> [nonempty_string()].
get_servers(Options) ->
    case lists:keysearch(verify_servers, 1, Options) of
	{value, {verify_servers, L}} when is_list(L) ->
	    L;
	false ->
	    %% Default is to query all public YubiCloud servers
	    ?YUBICO_VERIFY_SERVERS
    end.

-spec get_timeout(Options :: yubico_client_options()
		 ) -> non_neg_integer().
get_timeout(Options) ->
    case lists:keysearch(timeout, 1, Options) of
	{value, {timeout, Int}} when is_integer(Int) ->
	    Int;
	false ->
	    ?DEFAULT_TIMEOUT
    end.