%%% @doc The warden's public contract: three topics and three payloads.
%%%
%%% mcl-sentinel is built against exactly this, so every key and every topic
%%% segment is pinned here. A change that breaks one of these tests is a change
%%% to the contract, and it gets a new `_vN', not an edit.
-module(mcl_warden_facts_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REALM_NAME, <<"io.macula">>).

%%------------------------------------------------------------------------------
%% Topics
%%------------------------------------------------------------------------------

topics_are_the_published_contract_test() ->
    ?assertEqual(<<"io.macula/mcl-warden/warden/watch/attacker_sighted_v1">>,
                 mcl_warden_facts:topic(?REALM_NAME, attacker_sighted)),
    ?assertEqual(<<"io.macula/mcl-warden/warden/watch/attacker_ensnared_v1">>,
                 mcl_warden_facts:topic(?REALM_NAME, attacker_ensnared)),
    ?assertEqual(<<"io.macula/mcl-warden/warden/watch/warden_checked_in_v1">>,
                 mcl_warden_facts:topic(?REALM_NAME, warden_checked_in)).

%% macula's own parser is the judge of a canonical topic, not this module.
every_topic_is_a_canonical_app_fact_test() ->
    [begin
         {ok, Parsed} = macula_topic:parse(mcl_warden_facts:topic(?REALM_NAME, Fact)),
         ?assertMatch(#{tier := app, org := <<"mcl-warden">>, app := <<"warden">>,
                        domain := <<"watch">>, version := 1}, Parsed)
     end || Fact <- [attacker_sighted, attacker_ensnared, warden_checked_in]].

%%------------------------------------------------------------------------------
%% The realm name the topics carry must be the realm the pool publishes in
%%------------------------------------------------------------------------------

realm_name_hashing_to_the_realm_tag_is_accepted_test() ->
    ?assertEqual(ok, mcl_warden_facts:check_realm_name(
                       ?REALM_NAME, crypto:hash(sha256, ?REALM_NAME))).

%% A topic naming one realm published in another is a fact nobody subscribed
%% to hears. Refuse to boot rather than publish into that silence.
realm_name_for_another_realm_is_refused_test() ->
    Tag = crypto:hash(sha256, <<"org.example">>),
    ?assertError({mcl_warden_realm_name_mismatch, ?REALM_NAME, Tag},
                 mcl_warden_facts:check_realm_name(?REALM_NAME, Tag)).

%%------------------------------------------------------------------------------
%% Payloads
%%------------------------------------------------------------------------------

attacker_sighted_carries_the_indicator_and_attribution_test() ->
    Sighting = #{source_ip => <<"203.0.113.7">>, service => <<"ssh">>,
                 attempts => 7, window_s => 300,
                 usernames => [<<"root">>, <<"admin">>]},
    ?assertEqual(#{source_ip => <<"203.0.113.7">>, service => <<"ssh">>,
                   attempts => 7, window_s => 300,
                   usernames => [<<"root">>, <<"admin">>],
                   tenant_id => <<"acme-corp">>, label => <<"web-01">>,
                   at_ms => 1000},
                 mcl_warden_facts:attacker_sighted(Sighting, context())).

attacker_ensnared_carries_how_long_we_held_them_test() ->
    ?assertEqual(#{source_ip => <<"198.51.100.9">>, held_ms => 3600000,
                   tenant_id => <<"acme-corp">>, label => <<"web-01">>,
                   at_ms => 1000},
                 mcl_warden_facts:attacker_ensnared(<<"198.51.100.9">>, 3600000,
                                                    context())).

warden_checked_in_says_how_often_to_expect_it_test() ->
    ?assertEqual(#{tarpit => 0, interval_s => 60,
                   tenant_id => <<"acme-corp">>, label => <<"web-01">>,
                   at_ms => 1000},
                 mcl_warden_facts:warden_checked_in(context())).

warden_checked_in_carries_declared_coordinates_test() ->
    Ctx = (context())#{tarpit => 1, lat_e6 => 60170000, lng_e6 => 24940000},
    ?assertMatch(#{tarpit := 1, lat_e6 := 60170000, lng_e6 := 24940000},
                 mcl_warden_facts:warden_checked_in(Ctx)).

%% THE SENDER'S IDENTITY IS NOT IN THE PAYLOAD. macula 12 delivers every event
%% with the publisher its link verified; a self-asserted copy in the body is a
%% second answer that can only disagree with the first.
no_payload_names_its_own_publisher_test() ->
    [?assertEqual(false, maps:is_key(Key, Payload))
     || Payload <- every_payload(context()), Key <- [warden, reporter, type]].

%% Unset attribution is absent, never an `undefined' atom: an atom reaches a
%% non-BEAM subscriber as a string that looks like a real tenant.
unset_attribution_is_absent_test() ->
    Bare = #{tarpit => 0, at_ms => 1000},
    [begin
         ?assertEqual(false, maps:is_key(tenant_id, Payload)),
         ?assertEqual(false, maps:is_key(label, Payload))
     end || Payload <- every_payload(Bare)].

%% No booleans and no atoms anywhere on the wire: binaries, integers and lists
%% of binaries only.
payloads_hold_only_wire_safe_values_test() ->
    Ctx = (context())#{lat_e6 => 1, lng_e6 => 2},
    [?assert(wire_safe(V)) || Payload <- every_payload(Ctx), V <- maps:values(Payload)].

%%------------------------------------------------------------------------------
%% Attribution and coordinates come from app env; empty means unset
%%------------------------------------------------------------------------------

context_reads_attribution_from_app_env_test() ->
    with_env([{tenant_id, "acme-corp"}, {label, "web-01"},
              {lat_e6, "60170000"}, {lng_e6, "-24940000"},
              {tarpit_ports, [2222]}],
             fun() ->
                 ?assertMatch(#{tenant_id := <<"acme-corp">>, label := <<"web-01">>,
                                lat_e6 := 60170000, lng_e6 := -24940000,
                                tarpit := 1, at_ms := At} when is_integer(At),
                              mcl_warden_facts:context())
             end).

%% relx substitutes an unset variable as the empty string, so "" is how an
%% operator says "not set". It must not become a tenant called "".
context_drops_empty_and_malformed_values_test() ->
    with_env([{tenant_id, ""}, {label, ""}, {lat_e6, ""}, {lng_e6, "north"},
              {tarpit_ports, []}],
             fun() ->
                 Ctx = mcl_warden_facts:context(),
                 ?assertEqual([at_ms, tarpit], lists:sort(maps:keys(Ctx))),
                 ?assertMatch(#{tarpit := 0}, Ctx)
             end).

%%------------------------------------------------------------------------------
%% helpers
%%------------------------------------------------------------------------------

context() ->
    #{tenant_id => <<"acme-corp">>, label => <<"web-01">>, tarpit => 0,
      at_ms => 1000}.

every_payload(Ctx) ->
    [mcl_warden_facts:attacker_sighted(
       #{source_ip => <<"203.0.113.7">>, service => <<"ssh">>, attempts => 5,
         window_s => 300, usernames => [<<"root">>]}, Ctx),
     mcl_warden_facts:attacker_ensnared(<<"203.0.113.7">>, 1, Ctx),
     mcl_warden_facts:warden_checked_in(Ctx)].

wire_safe(V) when is_binary(V); is_integer(V) -> true;
wire_safe(L) when is_list(L) -> lists:all(fun is_binary/1, L);
wire_safe(_) -> false.

with_env(Pairs, Fun) ->
    [ok = application:set_env(mcl_warden, K, V) || {K, V} <- Pairs],
    try Fun()
    after [application:unset_env(mcl_warden, K) || {K, _} <- Pairs]
    end.
