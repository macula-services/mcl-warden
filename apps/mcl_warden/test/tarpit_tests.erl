%%% @doc The tarpit's cruelty, and its default of not existing.
-module(tarpit_tests).

-include_lib("eunit/include/eunit.hrl").

%% A junk pre-banner line must NEVER begin with "SSH-": that string is what ends
%% the game and lets the client's handshake proceed. If it ever leaks in, the
%% tarpit stops holding anyone.
never_sends_ssh_banner_test() ->
    [begin
         Line = tarpit_connection:junk_line(),
         ?assertNotMatch(<<"SSH-", _/binary>>, Line),
         ?assertMatch({_, _}, binary:match(Line, <<"\r\n">>))
     end || _ <- lists:seq(1, 2000)],
    ok.

%% SENSING-ONLY IS THE DEFAULT. A warden dropped in without configuration opens
%% no port at all; the tarpit is something an operator turns on.
%% Read from the shipped .app, not the live env, which other tests change.
no_decoy_port_is_bound_by_default_test() ->
    {ok, [{application, mcl_warden, Props}]} =
        file:consult(code:where_is_file("mcl_warden.app")),
    ?assertEqual([], proplists:get_value(tarpit_ports, proplists:get_value(env, Props))).

%% A connection held and then abandoned is reported with how long it was held.
an_abandoned_connection_is_reported_as_ensnared_test_() ->
    {setup,
     fun() ->
             Port = free_port(),
             ok = application:set_env(mcl_warden, tarpit_ports, [Port]),
             %% eunit runs setup and the test body in different processes, so
             %% the report goes to a name the test body registers.
             Report = fun(Ip, HeldMs) -> tarpit_tests_observer ! {ensnared, Ip, HeldMs}, ok end,
             {ok, Pid} = tarpit_listener:start_link(#{report => Report, drip_ms => 50}),
             {Pid, Port}
     end,
     fun({Pid, _Port}) ->
             unlink(Pid),
             gen_server:stop(Pid),
             application:unset_env(mcl_warden, tarpit_ports)
     end,
     fun({_Pid, Port}) ->
             fun() ->
                     true = register(tarpit_tests_observer, self()),
                     {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                                  [binary, {active, false}]),
                     {ok, Junk} = gen_tcp:recv(Sock, 0, 5000),
                     ?assertNotMatch(<<"SSH-", _/binary>>, Junk),
                     ?assertEqual(1, tarpit_listener:held()),
                     ok = gen_tcp:close(Sock),
                     {Ip, HeldMs} = await_ensnared(),
                     ?assertEqual(<<"127.0.0.1">>, Ip),
                     ?assert(is_integer(HeldMs) andalso HeldMs >= 0),
                     ?assertEqual(0, tarpit_listener:held())
             end
     end}.

%% THE CAP HOLDS. At the limit a new connection is closed, not held; a flood
%% fills the tarpit up to the cap and no further, so it cannot exhaust fds.
connections_past_the_cap_are_closed_test_() ->
    {setup,
     fun() ->
             Port = free_port(),
             ok = application:set_env(mcl_warden, tarpit_ports, [Port]),
             ok = application:set_env(mcl_warden, tarpit_max_conns, 1),
             Report = fun(_Ip, _HeldMs) -> ok end,
             {ok, Pid} = tarpit_listener:start_link(#{report => Report, drip_ms => 50}),
             {Pid, Port}
     end,
     fun({Pid, _Port}) ->
             unlink(Pid),
             gen_server:stop(Pid),
             application:unset_env(mcl_warden, tarpit_ports),
             application:unset_env(mcl_warden, tarpit_max_conns)
     end,
     fun({_Pid, Port}) ->
             fun() ->
                     Opts = [binary, {active, false}],
                     {ok, Held} = gen_tcp:connect({127, 0, 0, 1}, Port, Opts),
                     {ok, _Junk} = gen_tcp:recv(Held, 0, 5000),
                     {ok, Refused} = gen_tcp:connect({127, 0, 0, 1}, Port, Opts),
                     ?assertEqual({error, closed}, gen_tcp:recv(Refused, 0, 5000)),
                     ?assertEqual(1, tarpit_listener:held()),
                     ok = gen_tcp:close(Held)
             end
     end}.

%% --- helpers ---

free_port() ->
    {ok, L} = gen_tcp:listen(0, []),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

await_ensnared() ->
    receive {ensnared, Ip, HeldMs} -> {Ip, HeldMs}
    after 5000 -> error(no_ensnared_report)
    end.
