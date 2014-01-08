%%%-------------------------------------------------------------------
%%% File    : yubico_response.erl
%%% @author   Fredrik Thulin <fredrik@thulin.net>
%%% @doc      Verify and parse responses from Yubico servers.
%%%
%%% @since    11 Nov 2010 by Fredrik Thulin <fredrik@thulin.net>
%%% @end
%%%
%%% Copyright (c) 2010, Fredrik Thulin <fredrik@thulin.net>
%%% See the file LICENSE for full license.
%%%
%%%-------------------------------------------------------------------

-module(yubico_response).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
	 check_verify_response/6
	]).

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type yubico_server_error_response() :: 'backend_error' | 'bad_otp' | 'bad_signature' | 'missing_parameter' | 'no_status_in_response' | 'no_such_client' | 'not_enough_answers' | 'operation_not_allowed' | 'replayed_otp' | 'replayed_request'.

-type bad_auth_code() :: yubico_server_error_response() | 'not_authentic_response' | 'unknown_result'.


%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% @doc     Verify the authenticity of a 'verify' response from the
%%          Yubico server. If it is authentic, extract the status=
%%          information from it.
%%
%%            OTP    : string()
%%            APIkey : yubico:apikey()
%%            Nonce  : string()
%%            Body   : dict(), the response body as a dict
%%            Server : string()
%%            LogFun : yubico_log:logfun()
%%
%%          Returns :
%%
%%            {'auth','ok'} | {'bad_auth', bad_auth_code()}
%% @end
%%--------------------------------------------------------------------
-spec check_verify_response(OTP :: nonempty_string(),
			    APIkey :: yubico:apikey(),
			    Nonce :: nonempty_string(),
			    Body :: dict(),
			    Server :: nonempty_string(),
			    LogFun :: yubico_log:logfun()
			   ) -> {'auth','ok'} | {'bad_auth', bad_auth_code()}.
check_verify_response(OTP, APIkey, Nonce, Body, Server, LogFun) ->
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


%%====================================================================
%% Internal functions
%%====================================================================

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
	    HMAC = yubico_util:get_sha1_hmac(APIkey, Data2, LogFun),

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
