# Changelog

## 0.2.2 (2026-10-11)

- **Rebuilt on macula 14.8.1:** a fresh pool's direct dial now reuses a still-handshaking pinned link instead of dialing a duplicate connection the station replaces — the connect → `peer_closed` session loop seen on the Brussels enrollment (mcl-warden#3).

## 0.2.1 (2026-10-10)

- **Rebuilt on macula ~> 14 (newest release):** request admission frees the slot when the reply is sent, and caller attribution covers every payload shape (macula#89, macula#60).

## 0.2.0 (2026-10-07)

- **On `mcl_om` 0.39 with macula 14.2**, the SDK base every deployed service runs on
  (`~> 0.39`, released versions only). The info test's floors follow.
  (#2)

- **`/health` is served on a Unix socket only** (`/run/mcl/health.sock`, mcl_om 0.39 `health_socket`). No TCP
  health listener runs and no health port is bound on the host: `MCL_HEALTH_PORT`, the `health_port` setting and
  its `EXPOSE` are gone. The image creates `/run/mcl` and probes the socket; `scripts/health.sh` asks it through
  the container engine. A deploy that probed the port must probe the socket.

## 0.1.0 (2026-09-30)

- **On `mcl_om` 0.36 with macula 13.3**, the pair the fleet's stations speak (`~> 0.36`,
  released versions only). The info test's floors follow.

Ported from `hecate-services/hecate-warden` 0.2.4 onto `mcl_om` and macula 12.

- **On `mcl_om` 0.28 with macula 12.2.** The service answers `mcl-warden/info`,
  which mcl_om adds (public facts: versions, labels, health word, procedures),
  and a test sends that reply through macula's frame codec and checks it names
  this service and the mcl_om 0.28 / macula 12.2 pair. 0.28 is the release
  macula 12.2 needs: under 12.2 an older mcl_om lets a failed publish
  announcement kill the publishing process.
- **On `mcl_om` 0.27; the boot claim says which service, which box.** The claim
  carries `MCL_SERVICE_NAME=mcl-warden` and the host's `MCL_BOX`, shown on the
  realm's Providers desk. `MCL_BOX` is also every fact's label, replacing
  `MCL_WARDEN_LABEL`: one name for the box. 0.27 no longer brings barrel_docdb
  or rocksdb, which the warden never used.
- **The team image pair.** Builds in `macula-ci-otp` and runs on
  `macula-pq-runtime` (Debian trixie), both pinned by dated tag and digest,
  instead of floating `erlang:28-alpine` and `alpine:3.22`. CI runs in the same
  build image and adds dialyzer; `.tool-versions` moves to 28.4.3.

- **New fact contract.** Canonical macula app topics
  `<realm>/mcl-warden/warden/watch/{attacker_sighted,attacker_ensnared,warden_checked_in}_v1`
  replace `warden/threats`, `warden/ensnared` and `warden/presence`. Payloads no
  longer carry `type` or a self-asserted `warden` id: the verified publisher is
  the node identity macula delivers with every event. Unset `tenant_id`/`label`
  are omitted rather than sent as `undefined`. Timestamps are `at_ms`; the
  check-in carries `interval_s`.
- **One stored identity** from `/etc/mcl/secrets`, on a named volume, instead of
  a key minted per boot.
- **IPv6 sources are sensed.** The parser matched dotted quads only, so every
  attacker reaching sshd over IPv6 was invisible. Addresses are validated and
  reported in canonical form; IPv4-mapped addresses become the IPv4 address.
- **The tarpit cap holds.** A connection was set dripping before it was counted,
  so the refusal at the cap reached a holder no longer listening for it: the cap
  held nothing and the count drifted. Admission is now decided before the holder
  starts.
- **Sensing-only by default.** The application default bound three decoy ports
  while the documentation promised none; it now binds none.
- **Refuses to start** when the realm name the topics carry does not hash to the
  configured realm tag.
- The advertised `warden.report_threat` / `warden.ensnare` capabilities are gone;
  the warden serves nothing callable.
- Removed the fleet deploy, rearm and probe scripts.
