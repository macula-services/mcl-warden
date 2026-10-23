"""Generate mcl-warden's two C4 diagrams into assets/.

Run:  python3 architecture/c4_diagrams.py

  c4-context.svg     Level 1: what the service talks to
  c4-components.svg  Level 2: what it is made of

Drawn from the code, never from a template: the callbacks in
mcl_warden_service.erl, the three surfaces under mcl_warden_sup, the facts in
mcl_warden_facts.erl, the dependencies in rebar.config, the socket and volumes
in the Containerfile and deploy/docker-compose.yml. When one of those changes,
the diagram changes in the same commit.

Colours are plain classes with a prefers-color-scheme: dark block, no CSS custom
properties (rsvg-convert renders those black), so the SVGs render the same on
GitHub, in IDE previews and through rsvg-convert. After a change, render each
(rsvg-convert -w 1400 assets/c4-context.svg -o /tmp/c.png) and look at it; keep
architecture/README.md's tables in step.
"""
import os
from xml.sax.saxutils import escape

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")

SANS = '"Atkinson Hyperlegible", "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif'
MONO = '"JetBrains Mono", ui-monospace, Menlo, Consolas, monospace'

# Element kinds, each (light fill, light stroke, dark fill, dark stroke).
KINDS = {
    "b-sys": ("#F5E9CC", "#A56F0A", "#3A2E13", "#E3AA3C"),   # in scope
    "b-per": ("#E3EBF2", "#3B5B7A", "#1D2A36", "#8EB4D8"),   # person
    "b-mac": ("#E6E4EE", "#5E5A78", "#26243A", "#A9A4C8"),   # Macula infrastructure
    "b-ext": ("#ECEFED", "#8A9791", "#1C2421", "#7D8B85"),   # external system
    "b-cmp": ("#FFFFFF", "#8A9791", "#171F1C", "#7D8B85"),   # component or container
}

STYLE = f"""<style>
.t-name {{ font-family: {SANS}; font-size: 15px; font-weight: 700; }}
.t-desc {{ font-family: {SANS}; font-size: 12.5px; }}
.t-rel {{ font-family: {SANS}; font-size: 11.5px; paint-order: stroke; stroke-width: 4px; stroke-linejoin: round; }}
.t-code {{ font-family: {MONO}; font-size: 13px; font-weight: 600; }}
.t-type {{ font-family: {MONO}; font-size: 11.5px; }}
.t-bound {{ font-family: {MONO}; font-size: 12px; font-weight: 600; }}
.t-leg {{ font-family: {SANS}; font-size: 12px; }}
.edge {{ fill: none; stroke-width: 1.25; }}
.edge-later {{ fill: none; stroke-width: 1.25; stroke-dasharray: 5 4; }}
.bg {{ fill: #FFFFFF; }}
""" + "".join(f".{k} {{ fill: {v[0]}; stroke: {v[1]}; stroke-width: {2 if k == 'b-sys' else 1.25}; }}\n" for k, v in KINDS.items()) + """\
.b-later { fill: none; stroke: #8A9791; stroke-width: 1.25; stroke-dasharray: 5 4; }
.bound { fill: none; stroke: #B3BDB8; stroke-width: 1; }
.head { fill: #3B5B7A; }
.t-name, .t-code { fill: #16201D; }
.t-type, .t-bound, .t-leg { fill: #66736E; }
.t-desc { fill: #34413C; }
.t-rel { fill: #66736E; stroke: #FFFFFF; }
.edge, .edge-later { stroke: #8A9791; }
.arrowhead { fill: #8A9791; }
@media (prefers-color-scheme: dark) {
.bg { fill: #171F1C; }
""" + "".join(f".{k} {{ fill: {v[2]}; stroke: {v[3]}; }}\n" for k, v in KINDS.items()) + """\
.b-later { stroke: #7D8B85; }
.bound { stroke: #4A5752; }
.head { fill: #8EB4D8; }
.t-name, .t-code { fill: #E6ECE9; }
.t-type, .t-bound, .t-leg { fill: #93A09A; }
.t-desc { fill: #C3CDC8; }
.t-rel { fill: #93A09A; stroke: #171F1C; }
.edge, .edge-later { stroke: #7D8B85; }
.arrowhead { fill: #7D8B85; }
}
</style>"""

DEFS = ('<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path class="arrowhead" d="M0 0L10 5L0 10z"/></marker></defs>')

LEGEND = [("b-sys", "In scope"), ("b-per", "Person"), ("b-mac", "Macula infrastructure"),
          ("b-ext", "External system"), ("b-cmp", "Container or component")]
BOUNDARY = ("bound", "Boundary")


class Diagram:
    def __init__(self, name, title, w, h):
        self.name, self.title, self.w, self.h, self.parts = name, title, w, h, []

    def text(self, cls, x, y, s, anchor=None, rotate=None):
        a = f' text-anchor="{anchor}"' if anchor else ""
        r = f' transform="rotate({rotate} {x} {y})"' if rotate is not None else ""
        self.parts.append(f'<text class="{cls}" x="{x}" y="{y}"{a}{r}>{escape(s)}</text>')

    def box(self, cls, x, y, w, h, name, kind, desc, person=False, code=False):
        # A box that is too small for its own words renders as text on top of the
        # next box, which no test would catch and a reader would read as the
        # diagram saying something it does not. Fail here instead.
        need = 70 + 16 * max(len(desc) - 1, 0) + 18
        if h < need:
            raise ValueError(f"{self.name}: {name} needs height {need}, has {h}")
        for line in desc:
            if 16 + 6.2 * len(line) > w - 16:
                raise ValueError(f"{self.name}: {name}: '{line}' is wider than {w - 32}px")
        self.parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="{w}" height="{h}" rx="10"/>')
        tx = x + 16
        if person:
            self.parts.append(f'<circle class="head" cx="{x + 26}" cy="{y + 24}" r="9"/>')
            tx = x + 44
        self.text("t-code" if code else "t-name", tx, y + 28, name)
        self.text("t-type", tx, y + 46, kind)
        for i, line in enumerate(desc):
            self.text("t-desc", x + 16, y + 70 + 16 * i, line)

    def bound(self, x, y, w, h, label):
        self.parts.append(f'<rect class="bound" x="{x}" y="{y}" width="{w}" height="{h}" rx="12"/>')
        self.text("t-bound", x + 16, y + 22, label)

    def edge(self, d, later=False):
        self.parts.append(f'<path class="{"edge-later" if later else "edge"}" d="{d}" marker-end="url(#a)"/>')

    def legend(self, y, boundary=True):
        x = 24
        for cls, label in LEGEND + ([BOUNDARY] if boundary else []):
            self.parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="22" height="14" rx="3"/>')
            self.text("t-leg", x + 30, y + 12, label)
            x += 34 + 6.6 * len(label)

    def write(self):
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" role="img" '
               f'aria-label="{escape(self.title)}">', f"<title>{escape(self.title)}</title>", STYLE, DEFS,
               f'<rect class="bg" x="0" y="0" width="{self.w}" height="{self.h}"/>'] + self.parts + ["</svg>", ""]
        with open(os.path.join(OUT, self.name), "w") as f:
            f.write("\n".join(svg))


def context():
    d = Diagram("c4-context.svg", "mcl-warden system context", 1100, 780)
    d.box("b-ext", 40, 30, 320, 136, "An attacker", "[External system]",
          ["Fails logins on the box's real", "sshd, and probes whatever else is",
           "open, including the decoy ports", "when the tarpit is on."])
    d.box("b-per", 380, 30, 320, 136, "Service operator", "[Person]",
          ["Runs the box, sets the realm and", "the box label, opens the decoy",
           "ports, and lists the warden's node", "id where a sentinel reads it."])
    d.box("b-ext", 720, 30, 320, 136, "A sentinel, or any consumer", "[External system]",
          ["Subscribes to the three watch facts", "and builds its roster from the",
           "check-ins; attributes each one by", "the verified publisher."])
    d.box("b-sys", 390, 230, 320, 152, "mcl-warden", "[mcl_om mesh service]",
          ["Reads the host's auth log, holds", "attackers on decoy ports, and",
           "publishes what it sees on three", "facts. Holds no store; its own set is",
           "empty; it never blocks."])
    d.box("b-ext", 40, 470, 320, 136, "The box's sshd and auth log", "[External system]",
          ["sshd writes every failed login to", "its auth log; the directory is",
           "mounted read-only at /host/log.", "The sensor tails it by inode."])
    d.box("b-mac", 390, 470, 320, 136, "macula-realm", "[Macula infrastructure]",
          ["Endorses the node's identity key,", "admits the boot claim, and grants a",
           "provider authorization per org", "procedure."])
    d.box("b-mac", 720, 470, 320, 136, "Macula stations, mesh DHT", "[Macula infrastructure]",
          ["The pinned seeds in", "MACULA_STATION_SEEDS carry every fact",
           "over QUIC; the DHT holds a record", "for each org procedure."])

    d.edge("M180 166V200H440V230")
    d.text("t-rel", 188, 180, "fails logins, and probes the decoy ports")
    d.edge("M540 150V230")
    d.text("t-rel", 548, 192, "deploys; sets the realm and")
    d.text("t-rel", 548, 208, "the decoy ports")
    d.edge("M710 300H880V166")
    d.text("t-rel", 718, 292, "publishes the three watch facts")
    d.edge("M200 470V420H450V382")
    d.text("t-rel", 208, 440, "tails the log, read-only")
    d.edge("M550 382V470")
    d.text("t-rel", 558, 404, "boot claim")
    d.edge("M650 382V430H880V470")
    d.text("t-rel", 658, 422, "publishes the three facts")
    d.text("t-desc", 40, 640, "The warden never touches sshd, never blocks an address and never stores the log. It sees, it reports, and it holds a")
    d.text("t-desc", 40, 658, "decoy connection open for as long as the attacker is willing to wait.")
    d.legend(716, boundary=False)
    d.write()


def components():
    d = Diagram("c4-components.svg", "mcl-warden components", 1160, 1230)
    d.bound(16, 40, 1128, 750, "mcl-warden [Container: one OTP release]")

    d.box("b-cmp", 32, 70, 540, 120, "mcl_warden_app", "[OTP application]",
          ["Calls mcl_om:boot/1, which wires the mesh, the realm identity and health",
           "and then starts this service. Storeless: the service exports no store_id/0",
           "or data_dir/0, so no reckon-db is opened."], code=True)
    d.box("b-sys", 32, 222, 540, 152, "mcl_warden_service", "[mcl_om_service behaviour]",
          ["The callbacks mcl_om resolves by name. Its capabilities/0 is empty",
           "and mcl_om adds the open info and get_limits, info/0 included. health/0",
           "reports the SENSOR: down when the log is unreadable or the sensor is",
           "not answering, degraded when one that has read goes quiet for an hour.",
           "A dark mesh is not a failure."], code=True)
    d.box("b-cmp", 32, 406, 540, 120, "mcl_warden_sup", "[supervisor, one_for_one]",
          ["Three children, each owning its own work and publishing its own fact:",
           "sense_auth_log, tarpit_listener and check_in_warden. There is no central",
           "manager."], code=True)
    d.box("b-cmp", 32, 542, 540, 136, "mcl_warden_facts", "[the three published facts]",
          ["Builds and publishes attacker_sighted_v1, attacker_ensnared_v1 and",
           "warden_checked_in_v1 under <realm>/mcl-warden/warden/watch/. Values are",
           "binaries, integers and lists of binaries: no booleans (tarpit is 1/0), no",
           "atoms, no floats. tenant_id and label are self-asserted, not the sender."], code=True)

    d.bound(588, 70, 540, 700, "the warden's three surfaces, started by mcl_warden_sup")
    d.box("b-cmp", 604, 110, 508, 152, "sense_auth_log", "[gen_server, tails the auth log]",
          ["Polls the mounted log every 2 s and follows it across rotation by inode.",
           "Five failed logins from one source in five minutes publish",
           "attacker_sighted with the address, the count and the usernames tried; the",
           "same source is reported again at most every 10 minutes. IPv6 is lower-case",
           "and compressed, and an IPv4-mapped address is reported as IPv4."], code=True)
    d.box("b-cmp", 604, 294, 508, 136, "tarpit_listener", "[gen_server, binds the decoy ports]",
          ["Opt-in through MCL_WARDEN_TARPIT_PORTS, empty by default. Binds each decoy",
           "port, accepts every connection and hands it to a tarpit_connection, up to",
           "MCL_WARDEN_MAX_CONNS held at once; past the cap a connection is closed.",
           "It never reads a byte the attacker sends, and it never blocks anyone."], code=True)
    d.box("b-cmp", 604, 462, 508, 120, "tarpit_connection", "[one held connection]",
          ["Dribbles a random fake SSH pre-banner line every drip interval and never",
           "sends the line that would let the handshake begin, so a client waits.",
           "When the attacker gives up, held_ms is published as attacker_ensnared."], code=True)
    d.box("b-cmp", 604, 614, 508, 136, "check_in_warden", "[gen_server, the heartbeat]",
          ["Publishes warden_checked_in every 60 s with tarpit (1/0), interval_s and",
           "at_ms, so a consumer builds its roster live and never guesses the",
           "freshness window. A failed check-in is not fatal: the next interval tries",
           "again."], code=True)

    d.edge("M200 190V222"); d.text("t-rel", 208, 214, "boots with")
    d.edge("M200 358V390"); d.text("t-rel", 208, 388, "start/1 starts")
    d.edge("M572 450H588"); d.text("t-rel", 596, 450, "starts them")
    d.edge("M588 600H572"); d.text("t-rel", 596, 600, "each surface publishes through")
    d.edge("M858 430V462"); d.text("t-rel", 866, 454, "spawns one per connection")

    d.box("b-mac", 32, 822, 540, 152, "mcl_om", "[library, ~> 1.4]",
          ["boot/1: loads the node identity key, joins the realm, dials the pinned",
           "stations over QUIC, serves /health on a Unix socket at",
           "/run/mcl/health.sock, and starts the service: it registers the open",
           "info and get_limits every service carries. The facts publish through",
           "mcl_om_pubsub:publish/3."],
          code=True)
    d.box("b-mac", 588, 822, 540, 136, "macula", "[library, ~> 16.0, wire 1.0]",
          ["QUIC transport and the signed records the mesh DHT holds. Every fact",
           "carries the node identity its link verified, which is how a consumer",
           "attributes and allowlists this warden."], code=True)
    d.box("b-ext", 40, 990, 1080, 120, "The host", "[environment and mounts; both are in the compose file]",
          ["MCL_WARDEN_AUTH_LOG (the mounted host log), MCL_WARDEN_TARPIT_PORTS, MCL_WARDEN_MAX_CONNS, MCL_WARDEN_TENANT_ID,",
           "MCL_BOX, MCL_WARDEN_LAT_E6, MCL_WARDEN_LNG_E6, and the realm and station variables. The identity key is",
           "/etc/mcl/secrets/identity.key in the mcl-warden-secrets volume; the host's log directory is read-only at /host/log."],
          code=True)
    # From the application box itself, down the free corridor between the two columns, into mcl_om.
    d.edge("M300 190V198H24V900H32"); d.text("t-rel", 36, 808, "calls boot/1")
    # The facts publish through mcl_om's pubsub, so the edge ends at mcl_om, not at macula.
    d.edge("M450 678V800H300V822"); d.text("t-rel", 456, 786, "publishes through mcl_om")
    d.text("t-desc", 40, 1150, "config/sys.config.src fixes the org, mcl-warden, which the fact topics carry, and the realm name; the service refuses to start")
    d.text("t-desc", 40, 1168, "unless sha256 of that name is MCL_REALM. The log is mounted as a DIRECTORY, because a file bind-mount pins the inode and goes blind at the first logrotate.")
    d.legend(1206)
    d.write()


if __name__ == "__main__":
    for make in (context, components):
        make()
