%% @doc The mcl_om service contract for the warden.
%%
%% A deceptive threshold guard for a public box. It reads the host's auth log
%% for real attacks on the real sshd, optionally holds attackers in a tarpit on
%% decoy ports, and publishes what it sees as the three facts in
%% `mcl_warden_facts'. It never blocks, never stores the log, and holds no
%% event store: popped, an attacker gains a threat reporter for one box.
%%
%% SIX CALLBACKS, ALL REQUIRED. mcl_om resolves them BY NAME at startup, so the
%% `-behaviour' attribute below turns a missing one into a compile error.
-module(mcl_warden_service).

-behaviour(mcl_om_service).

-export([info/0, start/1, stop/1, health/0, capabilities/0, identity_spec/0]).
-export([node_id_hex/1]).

info() ->
    #{name => <<"mcl-warden">>,
      version => <<"0.1.0">>,
      description => <<"Deceptive threshold guard: senses intrusion attempts on a public box and reports them to the threat commons">>}.

%% The realm name the topics carry is checked against the realm the pool
%% publishes in before anything starts: a mismatch publishes where nobody
%% subscribed, and looks exactly like a quiet box.
%%
%% The node id is logged because it is how this warden is known: a sentinel
%% takes its reports only when this id is in its MCL_SENTINEL_WARDENS.
start(_Opts) ->
    ok = mcl_warden_facts:check_realm_name(),
    logger:notice("[warden] node id: ~s", [node_id_hex(mcl_om:identity_key())]),
    mcl_warden_sup:start_link().

%% @doc The node id a subscriber sees as this warden's verified publisher,
%% upper-case hex, or `none' on an ephemeral identity.
-spec node_id_hex({ok, macula_node_keys:node_key()} | {error, term()}) -> binary().
node_id_hex({ok, Key}) ->
    {ok, NodeId} = macula_node_keys:node_id(Key),
    binary:encode_hex(NodeId);
node_id_hex({error, _}) ->
    <<"none">>.

stop(_State) -> ok.

%% Health is the SENSOR's health, asserted rather than assumed. A dark mesh is
%% deliberately NOT a health failure: the warden keeps sensing and drops the
%% facts it cannot publish.
health() ->
    sensing(sensor_status()).

sensor_status() ->
    try sense_auth_log:status()
    catch _:_ -> unavailable
    end.

%% Not attached to anything: the path is missing or unreadable. Usually the
%% mount. Nothing this warden reports can be trusted, so do not say ok.
sensing(#{attached := false, path := Path}) ->
    {down, {auth_log_unreadable, Path}};
%% Attached, has read before, and has now been quiet far longer than any real
%% gap on a public box. This is the blind-but-alive state.
sensing(#{silent_ms := Silent}) when is_integer(Silent) ->
    quiet(Silent >= silence_limit_ms(), Silent);
%% Attached but has never read a byte since boot. Deliberately FAILS OPEN: a
%% warden freshly started on a genuinely quiet box must not cry broken.
sensing(#{}) ->
    ok;
%% The sensor did not answer at all (dead, or wedged past the call timeout).
sensing(_Unavailable) ->
    {down, sensor_unavailable}.

quiet(true, Silent)   -> {degraded, {auth_log_silent_ms, Silent}};
quiet(false, _Silent) -> ok.

silence_limit_ms() ->
    application:get_env(mcl_warden, auth_log_silence_ms, 3600000).

%% Nothing callable. The warden's whole output is its three published facts.
capabilities() -> [].

%% THE AUTHORITY THIS SERVICE ASKS THE REALM FOR, and deliberately nothing more.
identity_spec() ->
    #{scope => <<"mcl-warden">>,
      actions => [],
      resources => [],
      ttl_days => 30}.
