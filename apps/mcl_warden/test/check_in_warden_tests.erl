%%% @doc The heartbeat: once at boot, then on every interval.
-module(check_in_warden_tests).

-include_lib("eunit/include/eunit.hrl").

%% A box appears the moment it boots, not only when it first sees an attack,
%% and keeps appearing while it runs.
checks_in_at_boot_and_then_on_every_interval_test() ->
    Self = self(),
    CheckIn = fun() -> Self ! checked_in, ok end,
    {ok, Pid} = check_in_warden:start_link(#{check_in => CheckIn, interval_ms => 20}),
    [receive checked_in -> ok after 1000 -> error({missed_check_in, N}) end
     || N <- lists:seq(1, 3)],
    unlink(Pid),
    gen_server:stop(Pid).

%% The mesh being dark is not a reason for the heartbeat to die: the next
%% interval tries again.
a_failed_check_in_does_not_stop_the_heartbeat_test() ->
    Self = self(),
    CheckIn = fun() -> Self ! checked_in, error(mesh_dark) end,
    {ok, Pid} = check_in_warden:start_link(#{check_in => CheckIn, interval_ms => 20}),
    [receive checked_in -> ok after 1000 -> error({missed_check_in, N}) end
     || N <- lists:seq(1, 2)],
    ?assert(is_process_alive(Pid)),
    unlink(Pid),
    gen_server:stop(Pid).
