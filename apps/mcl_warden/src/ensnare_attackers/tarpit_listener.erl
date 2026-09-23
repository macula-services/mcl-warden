%%% @doc The tarpit: accept attacker connections and never let go.
%%%
%%% This is endlessh, in the language that was built for it. We bind the decoy
%%% ports, accept every connection, and hand each one to a `tarpit_connection'
%%% that dribbles an endless, slow, fake SSH banner. The attacker's scanner opens
%%% a socket expecting a handshake and instead waits... and waits. A well-behaved
%%% SSH client will sit there for hours before giving up. Every second it waits
%%% is a second it is not attacking anyone else, and it costs us a socket and a
%%% timer.
%%%
%%% We never READ a byte the attacker sends and never execute anything. There is
%%% no attack surface here beyond "accept a TCP connection and respond slowly",
%%% which is entirely our own resource and entirely our own business. Nothing
%%% reaches toward their machine.
%%%
%%% BEAM makes this trivial: tens of thousands of idle, timer-driven connections
%%% is the single most natural workload the VM has. On a threaded server each
%%% held connection costs a thread; here it costs a process at a few kilobytes.
-module(tarpit_listener).
-behaviour(gen_server).

-export([start_link/0, start_link/1, held/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(st, {socks = [] :: [{inet:port_number(), gen_tcp:socket()}],
             held  = 0  :: non_neg_integer(),
             max   = 4096 :: pos_integer(),
             report :: fun((binary(), non_neg_integer()) -> ok)}).

-define(DRIP_MS, 10000).

start_link() ->
    start_link(#{report => fun mcl_warden_facts:report_attacker_ensnared/2,
                 drip_ms => ?DRIP_MS}).

%% @doc `report' is told about every connection that gave up; `drip_ms' is how
%% long a holder waits between junk lines.
-spec start_link(#{report := fun((binary(), non_neg_integer()) -> ok),
                   drip_ms := pos_integer()}) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

%% @doc How many connections are currently ensnared.
-spec held() -> non_neg_integer().
held() ->
    gen_server:call(?MODULE, held).

init(#{report := Report, drip_ms := DripMs}) ->
    process_flag(trap_exit, true),
    Ports = env(tarpit_ports, []),
    Max = env(tarpit_max_conns, 4096),
    Socks = [listen(P) || P <- Ports],
    Listening = [S || S <- Socks, S =/= undefined],
    Server = self(),
    [spawn_link(fun() -> accept_loop(Server, LSock, DripMs) end) || {_P, LSock} <- Listening],
    logger:info("[warden] tarpit listening on ~p (max ~b held)",
                [[P || {P, _} <- Listening], Max]),
    {ok, #st{socks = Listening, max = Max, report = Report}}.

handle_call(held, _From, St) ->
    {reply, St#st.held, St};
%% The accept loop asks BEFORE the holder starts, so a refusal is a close and
%% never a connection that is already dripping. It used to start the holder and
%% then tell the server, which answered `drop' to a process no longer listening
%% for it: the cap held nothing and the count drifted.
handle_call(admit, _From, #st{held = Held, max = Max} = St) when Held >= Max ->
    {reply, refuse, St};
handle_call(admit, _From, St) ->
    {reply, admit, St#st{held = St#st.held + 1}};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_call}, St}.

handle_cast({released, _Pid, Ip, HeldMs}, #st{report = Report} = St) ->
    ok = Report(Ip, HeldMs),
    {noreply, St#st{held = max(0, St#st.held - 1)}};
handle_cast(_Msg, St) ->
    {noreply, St}.

%% One decoy port went away (listen socket closed).
handle_info({listen_gone, LSock}, St) ->
    {noreply, St#st{socks = lists:keydelete(LSock, 2, St#st.socks)}};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, St) ->
    [catch gen_tcp:close(LSock) || {_P, LSock} <- St#st.socks],
    ok.

%% --- Internal ---

%% Accept in a persistent loop that OWNS what it accepts, then immediately hands
%% each socket to a holder it spawns. The socket never passes through the
%% gen_server, so it is never orphaned by a dying accepting process (the bug that
%% made every connection close instantly). The gen_server only ever counts.
accept_loop(Server, LSock, DripMs) ->
    accepted(gen_tcp:accept(LSock), Server, LSock, DripMs).

accepted({ok, Conn}, Server, LSock, DripMs) ->
    {ok, Pid} = tarpit_connection:start(Conn, DripMs),
    handoff(gen_tcp:controlling_process(Conn, Pid), Conn, Pid, Server),
    accept_loop(Server, LSock, DripMs);
accepted({error, closed}, Server, LSock, _DripMs) ->
    Server ! {listen_gone, LSock};
accepted({error, _Reason}, Server, LSock, DripMs) ->
    accept_loop(Server, LSock, DripMs).

handoff(ok, _Conn, Pid, Server) ->
    admitted(gen_server:call(Server, admit), Pid);
handoff({error, _}, Conn, _Pid, _Server) ->
    catch gen_tcp:close(Conn).

admitted(admit, Pid)  -> tarpit_connection:go(Pid);
admitted(refuse, Pid) -> tarpit_connection:drop(Pid).

listen(Port) ->
    Opts = [binary, {packet, raw}, {active, false}, {reuseaddr, true},
            {backlog, 1024}, {send_timeout, 30000}],
    case gen_tcp:listen(Port, Opts) of
        {ok, LSock} ->
            {Port, LSock};
        {error, Reason} ->
            logger:warning("[warden] tarpit could not bind ~b: ~p", [Port, Reason]),
            undefined
    end.

env(Key, Default) ->
    application:get_env(mcl_warden, Key, Default).
