%%%-------------------------------------------------------------------
%%% File    : yubico_log.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      Logging interface.
%%%
%%%           The Erlang-Yubico client allows you to pass a function
%%%           to the top level API calls. This function should accept
%%%           three parameters :
%%%
%%%              Level  : 'debug', 'normal' or 'error'
%%%              Format : io:format format string
%%%              Data   : io:format data
%%%
%%%           This module also gives you a couple of standard ones to
%%%           use :
%%%
%%%              log_quiet()   : No logging (the default)
%%%              log_console() : Full logging to the Erlang console
%%%
%%% @since    7 Nov 2010 by Fredrik Thulin <fredrik@thulin.net>
%%% @end
%%%
%%% Copyright (c) 2010, Fredrik Thulin <fredrik@thulin.net>
%%% See the file LICENSE for full license.
%%%
%%%-------------------------------------------------------------------

-module(yubico_log).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
	 log/3,
	 log/4,

	 fun_quiet/0,
	 fun_console/0
	]).

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type loglevel() :: 'debug' | 'normal' | 'error'.
-type logfun() :: fun((Level :: loglevel(), Format :: string(), Data :: [any()]) -> 'ok').


%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% @doc     Perform a 'verify' web service request, using as sensible
%%          defaults as possible.
%%
%%            LogFun : Function of arity 3 that will be called to
%%                     do the actual logging.
%%            Level  : 'debug', 'normal' or 'error'
%%            Format : io:format format string
%%            Data   : io:format data
%%
%%          Returns :
%%
%%            ok
%% @end
%%--------------------------------------------------------------------
-spec log(LogFun :: logfun(),
	  Level :: loglevel(),
	  Format :: string()
	 ) -> ok.
log(LogFun, Level, Format) ->
    log(LogFun, Level, Format, []).

-spec log(LogFun :: logfun(),
	  Level :: loglevel(),
	  Format :: string(),
	  Data :: [any()]
	 ) -> any().
log(LogFun, Level, Format, Data) when is_function(LogFun) ->
    LogFun(Level, Format, Data);
log(_, _Level, _Format, _Data) ->
    %% quiet default
    ok.


%%--------------------------------------------------------------------
%% @doc     Provides a no-op LogFun.
%%
%%          Returns :
%%
%%            LogFun :: fun()
%% @end
%%--------------------------------------------------------------------
-spec fun_quiet() -> logfun().
fun_quiet() ->
    fun(_Level, _Format, _Data) ->
	    ok
    end.

%%--------------------------------------------------------------------
%% @doc     Provides a LogFun for logging (everything) to console.
%%
%%          Returns :
%%
%%            LogFun :: fun()
%% @end
%%--------------------------------------------------------------------
-spec fun_console() -> logfun().
fun_console() ->
    fun(Level, Format, Data) ->
	    %% Must do a single io:format to avoid getting screwed up output
	    %% when multiple processes log at the same time
	    Msg = io_lib:format(Format, Data),
	    io:format("~p (~p) Yubico: ~s~n", [self(), Level, Msg]),
	    ok
    end.
