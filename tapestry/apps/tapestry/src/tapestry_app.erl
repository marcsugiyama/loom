-module(tapestry_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    tap_mnesia:start(),
    pong = net_adm:ping('dobby@127.0.0.1'),
    tapestry_sup:start_link().

stop(_State) ->
    ok.
