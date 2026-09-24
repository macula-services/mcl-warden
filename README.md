# mcl-warden

**Deceptive threshold guard: senses intrusion attempts on a public box and reports them to the threat commons.**

This exists so every public box contributes what it is being attacked with to a
shared commons, and every box sees a campaign before it reaches the next door.

## Status

Built, tested locally, **not yet deployed**. Runs on macula 12 through
`mcl_om`. The consumer, `mcl-sentinel`, is being ported next and builds against
the fact contract below. This replaces `hecate-services/hecate-warden`, which ran
on macula 10 and inherits nothing: no identity, no volume, no topic.

## What it does

- **Senses.** Tails the host's auth log (mounted read-only) for failed logins on
  the box's real sshd, IPv4 and IPv6. When one source address fails 5 times in 5
  minutes it publishes `attacker_sighted`: the address, the count and the
  usernames tried. The same address is reported again at most every 10 minutes.
- **Ensnares** *(opt-in)*. Binds decoy ports (IPv4 only for now) and holds each
  connection open with an endless, slow stream of junk lines that an SSH client
  waits through before the banner it never gets. When the attacker gives up it publishes
  `attacker_ensnared` with how long it was held. Capped at `MCL_WARDEN_MAX_CONNS`
  held connections; past the cap a connection is closed.
- **Checks in** every 60 s with `warden_checked_in`, so a consumer builds its
  roster live.

It never blocks, never stores or forwards the log, and holds no event store.
Popped, an attacker gains a threat reporter for one box.

| Mode | Ports opened | Risk added |
|---|---|---|
| **Sensing-only** (default) | none | none: it reads a log that is already written |
| **Tarpit** | the decoy ports you list | those ports |

Never put the tarpit on the real sshd port unless admin SSH has moved first.

## The fact contract

Three canonical macula app facts, org `mcl-warden`, app `warden`, domain `watch`,
published in the realm the node is configured for:

| Topic | When |
|---|---|
| `<realm>/mcl-warden/warden/watch/attacker_sighted_v1` | a source crossed the threshold on the real sshd |
| `<realm>/mcl-warden/warden/watch/attacker_ensnared_v1` | the tarpit held a connection until it gave up |
| `<realm>/mcl-warden/warden/watch/warden_checked_in_v1` | heartbeat |

`<realm>` is the realm name, for example `io.macula`.

| Fact | Keys |
|---|---|
| `attacker_sighted` | `source_ip`, `service` (`ssh`), `attempts`, `window_s`, `usernames` (list), `at_ms` |
| `attacker_ensnared` | `source_ip`, `held_ms`, `at_ms` |
| `warden_checked_in` | `tarpit` (1/0), `interval_s`, `at_ms`, optional `lat_e6`, `lng_e6` |

Every fact also carries `tenant_id` (which organisation runs it) and `label`
(which box) when they are set, and omits them when they are not.

Rules a consumer can rely on:

- **The sender is not in the payload.** macula delivers every event with the
  publisher its link verified, which is this warden's stored node identity.
  Attribute and allowlist by that. `tenant_id` and `label` are self-asserted
  display attribution.
- Values are binaries, integers and lists of binaries. No booleans (`tarpit` is
  1/0), no floats (coordinates are integer micro-degrees), no atoms.
- `source_ip` is canonical: IPv6 is lower-case and compressed, and an
  IPv4-mapped address (`::ffff:a.b.c.d`) is reported as the IPv4 address, so one
  attacker is one key wherever it was seen.
- `at_ms` is milliseconds since the epoch.
- A change to any of this is a new `_v2` topic, not an edit. The contract is
  pinned in `apps/mcl_warden/test/mcl_warden_facts_tests.erl`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MCL_REALM` | required | 64-hex realm tag, sha256 of the realm name |
| `MCL_REALM_NAME` | required | the realm name the topics carry, e.g. `io.macula`. The service **refuses to start** unless its sha256 is `MCL_REALM` |
| `MCL_REALM_KEY` | required | the realm's public signing key, hex. The trust anchor, public material |
| `MACULA_STATION_SEEDS` | required | station hosts, `host[:port]`, comma-separated |
| `MACULA_STATION_NODE_IDS` | required | the matching 64-hex station node ids, index-paired |
| `MCL_WARDEN_TENANT_ID` | unset | who runs this warden, shown on every fact |
| `MCL_SERVICE_NAME` | `mcl-warden` | label on the boot claim the realm's operator sees on the Providers desk |
| `MCL_BOX` | unset | which box: on the boot claim, and on every fact as the warden's label |
| `MCL_WARDEN_LAT_E6` / `MCL_WARDEN_LNG_E6` | unset | declared map position, integer micro-degrees (Helsinki `60170000` / `24940000`). Self-asserted |
| `MCL_WARDEN_TARPIT_PORTS` | `[]` | decoy ports as an Erlang list, e.g. `[2222,2323]`. `[]` opens nothing |
| `MCL_WARDEN_MAX_CONNS` | `65536` | most tarpit connections held at once |
| `MCL_WARDEN_AUTH_LOG` | `/host/log/auth.log` | the log inside the container. RHEL family: `/host/log/secure` |
| `MCL_WARDEN_LOG_DIR` | `/var/log` | (compose) the host directory mounted read-only at `/host/log` |
| `MCL_HEALTH_PORT` | `8460` | health endpoint; host networking makes a clash a silent bind failure |

Two mounts matter, and `deploy/docker-compose.yml` has both:

- **The log directory, not the log file.** A file bind-mount pins the inode, so
  after the first logrotate the sensor reads a file that never grows again.
- **A named volume at `/etc/mcl/secrets`.** It holds the node identity key, which
  is the warden's verified identity on the mesh. Without the volume every
  recreate mints a new identity and every consumer that knew the warden forgets
  it.

### Admission

None. There is no admission step: a warden links on the PQ profile and the
identity puzzle, and invite-only is not enforced. A publish is refused only when
its realm does not match.

### Node id

At start the warden logs `[warden] node id: <64 hex>`. That is the id every
consumer sees as this warden's verified publisher, and the one to list in
mcl-sentinel's `MCL_SENTINEL_WARDENS`. It is stable as long as the identity
volume is.

## Health

`/health` reports the **sensor**, because a warden that is alive but blind looks
exactly like a quiet night:

- `down` when the log is missing or unreadable (usually the mount) or the sensor
  is not answering;
- `degraded` when a sensor that has been reading has seen nothing for an hour;
- `ok` otherwise, including a fresh start on a box that has had no traffic yet.

A dark mesh is not a health failure: the warden keeps sensing and drops the
facts it cannot publish.

`scripts/health.sh [host]` asks a running node.

## Deploy

What an operator does, in order:

1. Set `MCL_REALM` (the 64-hex tag) **and** `MCL_REALM_NAME` (`io.macula`); the
   warden refuses to start unless sha256 of the name is the tag.
2. Mount the host's log directory read-only and a **named** volume at
   `/etc/mcl/secrets` (both are in `deploy/docker-compose.yml`).
3. Start it and read `[warden] node id: <64 hex>` from the log. Add that id to
   mcl-sentinel's `MCL_SENTINEL_WARDENS`, or the sentinel ignores this warden.
4. Leave `MCL_WARDEN_TARPIT_PORTS=[]` unless decoy ports are open in the firewall.

## Build and test

    rebar3 eunit
    rebar3 lint

OTP 28.4.3, pinned in `.tool-versions`, the `Containerfile` and CI, and a test
fails when they disagree with the VM running it. The image builds in the team's
`ghcr.io/macula-io/macula-ci-otp` and runs on `ghcr.io/macula-io/macula-pq-runtime`
(Debian trixie, OpenSSL with ML-DSA), both pinned by dated tag and digest; CI
runs in the same build image. macula's NIFs build from source there.

## Deployment

CI pushes `ghcr.io/macula-services/mcl-warden:latest` on every push to `main`
that touches code, and the semver tag on a `v*` tag. Under watchtower a push to
`main` is a deploy; a rollback pins a semver tag.

## License

Apache-2.0. See [LICENSE](LICENSE).
