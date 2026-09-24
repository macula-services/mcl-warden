%% @doc The service contract, asserted locally.
%%
%% mcl_om resolves its six callbacks BY NAME at startup, on a live node, so a
%% service that forgets one dies with `undef' where nobody is watching. The
%% primary defence is the `-behaviour(mcl_om_service)' attribute on the
%% service module, which turns a missing callback into a compile error under
%% warnings_as_errors.
%%
%% What this suite adds is everything the compiler cannot see: that the attribute
%% has not been quietly dropped, that the values inside those callbacks are the
%% shapes mcl_om will destructure, and that the names and version this service
%% reports are the ones it actually has. Nothing local boots mcl_om, so
%% asserting the shape by hand is the closest available thing to a rehearsal.
-module(mcl_warden_service_tests).

-include_lib("eunit/include/eunit.hrl").

-define(APP, mcl_warden).
-define(SERVICE, mcl_warden_service).

%% Belt and braces with the behaviour attribute, and it survives the attribute
%% being removed. If mcl_om ever adds a SEVENTH required callback this test
%% keeps passing and the deploy still breaks, which is the honest limit of a
%% local assertion about a remote contract.
exports_every_required_callback_test() ->
    _ = code:ensure_loaded(?SERVICE),
    Required = [{info, 0}, {start, 1}, {stop, 1},
                {health, 0}, {capabilities, 0}, {identity_spec, 0}],
    Missing = [F || {N, A} = F <- Required,
                    not erlang:function_exported(?SERVICE, N, A)],
    ?assertEqual([], Missing).

info_carries_the_three_keys_test() ->
    #{name := Name, version := Vsn, description := Desc} = ?SERVICE:info(),
    ?assert(is_binary(Name)),
    ?assert(is_binary(Vsn)),
    ?assert(is_binary(Desc)),
    ?assertEqual(<<"mcl-warden">>, Name).

%% THE TWO NAMES MUST AGREE. The OTP application is snake_case because it is an
%% Erlang atom; the repository, the container image and the name this service
%% answers to on the mesh are kebab-case. They describe one service, so a
%% scaffold generated with a mismatched pair is caught here on the first eunit
%% run rather than by a puzzled reader months later.
mesh_name_matches_the_application_test() ->
    #{name := Wire} = ?SERVICE:info(),
    Snake = atom_to_binary(?APP, utf8),
    ?assertEqual(binary:replace(Snake, <<"_">>, <<"-">>, [global]), Wire).

%% The version in info/0 is what a peer reads off /health, so it disagreeing with
%% the application it describes is a lie that nothing else would catch.
info_version_matches_the_application_test() ->
    _ = application:load(?APP),
    {ok, Vsn} = application:get_key(?APP, vsn),
    #{version := Reported} = ?SERVICE:info(),
    ?assertEqual(list_to_binary(Vsn), Reported).

%% The warden serves nothing callable: its whole output is the three facts in
%% mcl_warden_facts. Adding a capability breaks this test on purpose, so that
%% someone writes down what the warden can now be asked to do.
announces_no_capability_test() ->
    ?assertEqual([], ?SERVICE:capabilities()).

identity_spec_has_the_shape_mcl_om_expects_test() ->
    #{scope := Scope, actions := Actions,
      resources := Resources, ttl_days := Ttl} = ?SERVICE:identity_spec(),
    ?assert(is_binary(Scope)),
    ?assert(is_list(Actions)),
    ?assert(is_list(Resources)),
    ?assert(is_integer(Ttl) andalso Ttl > 0).

%% A resource this service is not authorised for is a publish the realm would
%% refuse once UCAN delegation lands. Asking for nothing and claiming nothing
%% must stay in step, so the two are asserted together.
authority_matches_what_is_announced_test() ->
    #{actions := Actions, resources := Resources} = ?SERVICE:identity_spec(),
    ?assertEqual([], ?SERVICE:capabilities()),
    ?assertEqual([], Actions),
    ?assertEqual([], Resources).

%% The supervisor starts and stops cleanly on its own, without mcl_om: one
%% child per surface, and no central manager. With no decoy ports configured
%% the tarpit binds nothing, and with no mesh the check-in logs and retries.
supervisor_starts_its_three_surfaces_test() ->
    {ok, Pid} = mcl_warden_sup:start_link(),
    ?assert(is_process_alive(Pid)),
    ?assertEqual([check_in_warden, sense_auth_log, tarpit_listener],
                 lists:sort([Id || {Id, _, _, _} <- supervisor:which_children(Pid)])),
    unlink(Pid),
    exit(Pid, shutdown),
    wait_down(Pid).

%% An operator lists this warden in mcl-sentinel's MCL_SENTINEL_WARDENS by its
%% node id, and the log line at start is where they read it. It must be the id
%% a subscriber sees as the verified publisher: upper-case hex of the node id.
node_id_is_the_publisher_id_a_sentinel_lists_test() ->
    {ok, Key} = macula_node_keys:generate(identity, pq_hybrid, #{puzzle_difficulty => 0}),
    {ok, NodeId} = macula_node_keys:node_id(Key),
    ?assertEqual(binary:encode_hex(NodeId), ?SERVICE:node_id_hex({ok, Key})),
    ?assertEqual(<<"none">>, ?SERVICE:node_id_hex({error, no_identity_key})).

%% A warden with no realm publishes into nothing, and one whose realm name is
%% not the realm it is in publishes where nobody listens. Both refuse to start.
start_refuses_without_a_realm_test() ->
    ok = application:set_env(mcl_warden, realm_name, "io.macula"),
    try
        ?assertError({mcl_warden_realm_unset, <<"io.macula">>, _}, ?SERVICE:start(#{}))
    after
        application:unset_env(mcl_warden, realm_name)
    end.

start_refuses_without_a_realm_name_test() ->
    ?assertError({mcl_warden_realm_name_unset, realm_name}, ?SERVICE:start(#{})).

wait_down(Pid) ->
    Ref = monitor(process, Pid),
    receive {'DOWN', Ref, process, Pid, _} -> ok after 5000 -> error(sup_alive) end.

%%==============================================================================
%% Health is the SENSOR's health
%%==============================================================================

%% health/0 returned a bare ok for most of the warden's life. It checked
%% nothing, so when the fleet went blind on 2026-07-26 every container went on
%% reporting healthy for two days. These pin each state it can now report.
health_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun attached_but_never_read_fails_open/1,
      fun reading_is_healthy/1,
      fun silence_past_the_limit_is_degraded/1,
      fun an_unreadable_log_is_down/1,
      fun a_dead_sensor_is_down/1]}.

setup() ->
    Dir = filename:join(["/tmp", "mcl-warden-health-" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Path = filename:join(Dir, "auth.log"),
    ok = file:write_file(Path, <<>>),
    ok = application:set_env(mcl_warden, auth_log, Path),
    ok = application:set_env(mcl_warden, auth_log_silence_ms, 3600000),
    #{dir => Dir, path => Path}.

cleanup(#{dir := Dir}) ->
    stop(whereis(sense_auth_log)),
    application:unset_env(mcl_warden, auth_log_silence_ms),
    _ = os:cmd("rm -rf " ++ Dir),
    ok.

stop(undefined) -> ok;
stop(Pid)       -> gen_server:stop(Pid).

%% A warden freshly started on a genuinely quiet box has read nothing yet. That
%% is not a fault, and reporting it as one would make the signal useless.
attached_but_never_read_fails_open(_Ctx) ->
    fun() ->
        start_sensor(),
        ?assertEqual(ok, mcl_warden_service:health())
    end.

reading_is_healthy(#{path := Path}) ->
    fun() ->
        start_sensor(),
        append(Path, failed_auth_line(<<"203.0.113.10">>)),
        poll(),
        ?assertEqual(ok, mcl_warden_service:health())
    end.

%% THE ONE THAT MATTERED. Alive, attached, and reading nothing. With the limit
%% dropped to zero, any completed read is already "too long ago", which is the
%% blind-but-healthy state the fleet sat in.
silence_past_the_limit_is_degraded(#{path := Path}) ->
    fun() ->
        start_sensor(),
        append(Path, failed_auth_line(<<"203.0.113.20">>)),
        poll(),
        ok = application:set_env(mcl_warden, auth_log_silence_ms, 0),
        ?assertMatch({degraded, {auth_log_silent_ms, _}}, mcl_warden_service:health())
    end.

%% No log at the path at all. In production this is the mount being wrong, which
%% is precisely how the outage started.
an_unreadable_log_is_down(#{dir := Dir}) ->
    fun() ->
        Missing = filename:join(Dir, "no-such-auth.log"),
        ok = application:set_env(mcl_warden, auth_log, Missing),
        start_sensor(),
        ?assertEqual({down, {auth_log_unreadable, Missing}}, mcl_warden_service:health())
    end.

a_dead_sensor_is_down(_Ctx) ->
    fun() ->
        start_sensor(),
        gen_server:stop(whereis(sense_auth_log)),
        ?assertEqual({down, sensor_unavailable}, mcl_warden_service:health())
    end.

%% --- health helpers ---

start_sensor() ->
    {ok, _} = sense_auth_log:start_link(),
    poll().

poll() ->
    sense_auth_log ! poll,
    _ = sys:get_state(sense_auth_log),
    ok.

append(Path, Data) ->
    {ok, Fd} = file:open(Path, [append, binary, raw]),
    ok = file:write(Fd, Data),
    ok = file:close(Fd).

failed_auth_line(Ip) ->
    iolist_to_binary(["Jul 28 04:00:00 host sshd[1]: Failed password for root from ",
                      Ip, " port 4021 ssh2\n"]).

%%==============================================================================
%% The runtime is pinned in two places, and neither is the one you are running
%%==============================================================================

%% ⚠ THIS GUARD EXISTS BECAUSE A SIBLING SERVICE DID NOT HAVE IT, AND IT COST
%% THREE COMMITS AND AN IMAGE THAT SHIPPED ANYWAY.
%%
%% Its `Containerfile' said 27 while development ran on 28. So `rebar3 eunit'
%% passing locally meant "passing on 28" and nothing more, CI failed on a crash
%% that does not occur on 28 at all, and because the image build is a separate
%% workflow the image went to the fleet regardless.
%%
%% The release is pinned in TWO files, and the version actually running is a
%% third thing that agrees with neither by default. **A comment in each file
%% saying they must match is not a mechanism**, and both files carried one.
%%
%% ⚠⚠ IT FAILS RATHER THAN WARNS WHEN YOUR VM DIFFERS, AND THAT IS DELIBERATE.
%% Developing on a release you do not ship makes a green suite mean less than it
%% appears to. If you want to work on another release, move both pins and find
%% out what breaks, which is the whole point of having them.
the_runtime_agrees_between_the_image_the_ci_and_this_vm_test() ->
    %% The team images' tags name a date, not a release, so the builder and
    %% lint each assert the release in a check step; this compares those, the
    %% .tool-versions pin and this VM, to the patch.
    Check = "\\{<<\"([0-9]+\\.[0-9]+\\.[0-9]+)\">>, true\\} -> halt\\(0\\);",
    Image = pinned("Containerfile", Check),
    CiCheck = pinned(".github/workflows/lint.yml", Check),
    Tools = pinned(".tool-versions", "^erlang ([0-9]+\\.[0-9]+\\.[0-9]+)$"),
    %% Sorted and deduplicated, so a failure prints every version rather than
    %% the first pair that happened to be compared.
    ?assertEqual([Image], lists:usort([Image, CiCheck, Tools, running_otp()])).

%% Build, CI and runtime are the team pair, named by dated tag AND digest, so a
%% re-pushed tag cannot change what builds or what runs.
images_are_the_digest_pinned_team_pair_test() ->
    Digest = ":[0-9]{8}-[0-9]{4}@sha256:[0-9a-f]{64}",
    ?assertMatch(<<_/binary>>,
                 pinned("Containerfile",
                        "^FROM (ghcr\\.io/macula-io/macula-ci-otp)" ++ Digest ++ " AS builder$")),
    ?assertMatch(<<_/binary>>,
                 pinned("Containerfile",
                        "^FROM (ghcr\\.io/macula-io/macula-pq-runtime)" ++ Digest ++ "$")),
    ?assertMatch(<<_/binary>>,
                 pinned(".github/workflows/lint.yml",
                        "^\\s+image: (ghcr\\.io/macula-io/macula-ci-otp)" ++ Digest ++ "$")).

%% The full release, 28.4.3 and not 28: `otp_release' names only the major.
running_otp() ->
    {ok, Version} = file:read_file(filename:join([code:root_dir(), "releases",
                                                  erlang:system_info(otp_release),
                                                  "OTP_VERSION"])),
    string:trim(Version).

pinned(Relative, Pattern) ->
    {ok, Text} = file:read_file(alongside(Relative)),
    {match, [Version]} = re:run(Text, Pattern,
                                [multiline, {capture, all_but_first, binary}]),
    Version.

%% Relative to the beam rather than the working directory, because eunit runs
%% from wherever the developer happens to be standing.
alongside(Name) -> climb(filename:dirname(code:which(?MODULE)), Name, 8).

climb(_Dir, Name, 0) -> Name;
climb(Dir, Name, Left) ->
    Candidate = filename:join(Dir, Name),
    found(filelib:is_regular(Candidate), Candidate, Dir, Name, Left).

found(true, Candidate, _Dir, _Name, _Left) -> Candidate;
found(false, _Candidate, Dir, Name, Left) ->
    climb(filename:dirname(Dir), Name, Left - 1).

%%==============================================================================
%% The boot claim names the service and its box
%%==============================================================================

%% Every node that claims on the realm shows its service and host on the
%% Providers desk: mcl_om 0.27 reads MCL_SERVICE_NAME and MCL_BOX. The service
%% name is ours; the box is the deploying host's to say.
the_claim_names_the_service_and_its_box_test() ->
    {ok, Text} = file:read_file(alongside("deploy/docker-compose.yml")),
    ?assertMatch({match, _}, re:run(Text, <<"- MCL_SERVICE_NAME=mcl-warden\\n">>)),
    ?assertMatch({match, _}, re:run(Text, <<"- MCL_BOX=\\$\\{MCL_BOX:-\\}\\n">>)).

%% ⚠ NOT IN sys.config. mcl_om prefers its app env to the OS variables, so a
%% `service_name' or `box' line there, even an empty one, would hide the two
%% variables above (until mcl_om 0.27.1 treats empty as unset).
the_claim_labels_are_not_shadowed_by_app_env_test() ->
    {ok, Text} = file:read_file(alongside("config/sys.config.src")),
    ?assertEqual(nomatch, re:run(Text, <<"^\\s*\\{(service_name|box),">>, [multiline])).

