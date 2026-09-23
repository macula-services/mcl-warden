%%% @doc The warden checks in with the commons on a heartbeat, so a consumer
%%% builds its roster live instead of from a hard-coded box list.
%%%
%%% A box appears the moment it boots, not only when it first sees an attack,
%%% and drops off when its check-ins stop. The fact says how often to expect the
%%% next one (`interval_s'), so a consumer never has to guess the freshness
%%% window. A failed check-in is not fatal: the next interval tries again.
-module(check_in_warden).

-behaviour(gen_server).

-export([start_link/0, start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link() ->
    start_link(#{check_in => fun mcl_warden_facts:check_in/0,
                 interval_ms => mcl_warden_facts:check_in_interval_ms()}).

-spec start_link(#{check_in := fun(() -> ok), interval_ms := pos_integer()}) ->
    {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

init(Opts) ->
    self() ! check_in,
    {ok, Opts}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(check_in, #{check_in := CheckIn, interval_ms := Interval} = St) ->
    attempt(CheckIn),
    erlang:send_after(Interval, self(), check_in),
    {noreply, St};
handle_info(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, _St) -> ok.

attempt(CheckIn) ->
    try CheckIn()
    catch Class:Reason ->
        logger:warning("[warden] check-in failed: ~p:~p", [Class, Reason])
    end.
