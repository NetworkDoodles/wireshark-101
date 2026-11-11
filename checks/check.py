"""make check T=1.1 · CH=1 · (nothing)  ·  verifies a task, a chapter or the whole lab.

Every answer is checked against the capture it came from: the checker reads your captures/<task>.pcapng with
tshark (the same dissectors as Wireshark) and works out what the right answer is for *that* file. Filters are
checked by what they match in the reference capture pcaps/mixed.pcapng, so any filter that picks exactly the
right packets passes, not just ours.

    python checks/check.py 1.1          one task
    python checks/check.py ch1          one chapter
    python checks/check.py all          everything
"""
import binascii
import ipaddress
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "lab").as_posix())
import lab  # noqa: E402

GUIDE = "https://networkdoodles.com/labs/wireshark-101"
MIXED = lab.PCAPS / "mixed.pcapng"
LAPTOP = lab.MAC["laptop"]
TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
C = {k: (v if TTY else "") for k, v in dict(g="\033[32m", r="\033[31m", y="\033[33m", c="\033[36m", d="\033[2m",
                                              b="\033[1m", x="\033[0m").items()}


# ── reading your answers ───────────────────────────────────────────────────────
def answers(task):
    """answers/<task>.yml as a dict of strings. Read line by line, not as YAML: YAML would turn a MAC
    address made only of digits into a number, and a display filter full of colons and quotes into a mess."""
    p = ROOT / "answers" / f"{task}.yml"
    doc = {}
    for line in (p.read_text().splitlines() if p.exists() else []):
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.split(" #")[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        doc[key.strip()] = value
    return doc


def blank(v):
    return v is None or str(v).strip() == ""


def norm_mac(v):
    """aa:aa:aa:11:11:11, AA-AA-AA-11-11-11 and aaaa.aa11.1111 are all the same MAC address."""
    if str(v).strip().lower() in ("broadcast", "ff:ff:ff:ff:ff:ff"):
        return "ff:ff:ff:ff:ff:ff"
    hexdigits = re.sub(r"[^0-9a-f]", "", str(v).lower())
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)) if len(hexdigits) == 12 else None


def norm_ip(v):
    try:
        return str(ipaddress.IPv4Address(str(v).strip()))
    except ValueError:
        return None


def norm_int(v):
    s = str(v).strip().replace(",", "")
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return int(s, 16)
    return int(s) if s.isdigit() else None


def norm_word(v):
    s = str(v).strip().lower().rstrip(".")
    return s or None


def norm_words(v):
    """'web.lab, intranet.lab' and 'intranet.lab web.lab' are the same set of names."""
    words = {w.strip().lower().rstrip(".") for w in re.split(r"[,\s]+", str(v)) if w.strip()}
    return frozenset(words) or None


def norm_tls(v):
    """'1.3', 'TLS 1.3', 'TLSv1.3' and '0x0304' are all TLS 1.3."""
    s = str(v).strip().lower().replace(" ", "")
    hexes = {"0x0303": "1.2", "0x0304": "1.3", "0x0302": "1.1", "0x0301": "1.0"}
    if s in hexes:
        return hexes[s]
    m = re.fullmatch(r"(?:tls)?v?(1\.[0-3])", s)
    return m.group(1) if m else None


CIPHERS = {0x1301: "tls_aes_128_gcm_sha256", 0x1302: "tls_aes_256_gcm_sha384",
           0x1303: "tls_chacha20_poly1305_sha256", 0xc02f: "tls_ecdhe_rsa_with_aes_128_gcm_sha256",
           0xc030: "tls_ecdhe_rsa_with_aes_256_gcm_sha384", 0xcca8: "tls_ecdhe_rsa_with_chacha20_poly1305_sha256"}


def norm_cipher(v):
    """A cipher suite by its number (0x1302) or its name (TLS_AES_256_GCM_SHA384)."""
    s = str(v).strip().lower()
    n = norm_int(s)
    if n is not None:
        return n
    for num, name in CIPHERS.items():
        if s.replace("-", "_") == name:
            return num
    return None


def norm_rcode(v):
    names = {"noerror": 0, "no error": 0, "formerr": 1, "servfail": 2, "nxdomain": 3, "no such name": 3,
             "notimp": 4, "refused": 5}
    s = str(v).strip().lower()
    return int(s) if s.isdigit() else names.get(s)


NORM = {"mac": norm_mac, "ip": norm_ip, "int": norm_int, "word": norm_word, "words": norm_words,
        "tls": norm_tls, "cipher": norm_cipher, "rcode": norm_rcode}
WHAT = {"mac": "MAC address", "ip": "IPv4 address", "int": "whole number", "word": "name", "words": "list of names",
        "tls": "TLS version, like 1.2", "cipher": "cipher suite (its name or its number, like 0x1301)",
        "rcode": "DNS response code, like NXDOMAIN"}


def ask(doc, key, kind, want, label, hint="but that's not what the capture says. Look again."):
    """One answer against the value(s) the capture holds, with a message that doesn't give it away."""
    given = doc.get(key)
    if blank(given):
        return False, f"{label}: {key} is still blank in the answers file"
    value = NORM[kind](given)
    if value is None:
        return False, f"{label}: {given!r} isn't a {WHAT[kind]}"
    if want is None:
        return False, f"{label}: the capture doesn't hold this at all. Was it taken during the right traffic?"
    wants = want if isinstance(want, (set, list, tuple)) else {want}
    wants = {NORM[kind](w) if isinstance(w, str) else w for w in wants}
    if value in wants:
        return True, f"{label}: {given}"
    return False, f"{label}: you wrote {given}, {hint}"


# ── reading the captures ───────────────────────────────────────────────────────
# How each capture task's file is made, and what it has to contain.
CAPTURE = {
    "1.1": ("laptop:eth1", "ping", "icmp"),
    "1.2": ("sw1:eth1,sw1:eth3", "crossping", "icmp"),
    "2.2": ("laptop:eth1", "mixed", "dns"),
    "3.1": ("laptop:eth1", "arp", "arp"),
    "3.2": ("laptop:eth1", "dupip", "arp"),
    "4.1": ("laptop:eth1", "dhcp", "dhcp"),
    "4.2": ("sw1:eth1,r1:eth2", "dhcp", "dhcp"),
    "5.1": ("laptop:eth1", "dns", "dns"),
    "5.2": ("laptop:eth1", "search", "dns"),
    "6.1": ("laptop:eth1", "web", "http"),
    "6.2": ("laptop:eth1", "refused", "tcp.flags.reset == 1"),
    "7.1": ("laptop:eth1", "tls", "tls.handshake"),
    "7.2": ("laptop:eth1", "tls12", "tls.handshake"),
    "8.1": ("laptop:eth1", "big", "tcp"),
    "8.2": ("laptop:eth1,r1:eth2,r2:eth2", "webip", "tcp"),
    "8.3": ("laptop:eth1,sw1:eth1", "tls", "tcp"),
}
FILTER = {"2.2": "udp port 53"}


def how(t):
    at, x, _ = CAPTURE[t]
    extra = f' F="{FILTER[t]}"' if t in FILTER else ""
    return f"make capture AT={at} NAME={t} X={x}{extra}"


def captured(t):
    """The task's capture, checked: it exists, it was taken where the task says, and it has the traffic."""
    pcap = lab.capture_file(t)
    if not pcap:
        return None, (False, f"there's no captures/{t}.pcapng yet. Take it:  {how(t)}"
                             f"   (no lab? make skip T={t} uses the reference capture)")
    at, _, needs = CAPTURE[t]
    want = set(at.split(","))
    got = lab.interfaces(pcap)
    if got != want:
        return None, (False, f"captures/{t}.pcapng was taken on {', '.join(sorted(got)) or 'nothing'}, "
                             f"not {', '.join(sorted(want))}. Take it again:  {how(t)}")
    if lab.count(pcap, needs) == 0:
        return None, (False, f"captures/{t}.pcapng has no '{needs}' in it. Was the traffic sent while it ran? {how(t)}")
    return pcap, (True, f"captures/{t}.pcapng: taken on {', '.join(sorted(got))}, {lab.count(pcap, '')} frames")


def on(iface, flt):
    return f'frame.interface_name == "{iface}" && ({flt})'


def col(pcap, flt, name):
    return [r[0] for r in lab.fields(pcap, flt, name) if r and r[0]]


# ── the truth: what each answer should be, for a given capture ─────────────────
# solve.py fills in answers from these same functions.
def truth_1_1(p):
    replies = lab.fields(p, "icmp.type == 0", "eth.src", "ip.ttl")
    return {"first_protocol": (lab.first(p, f"eth.src == {LAPTOP}", "_ws.col.protocol") or "").lower() or None,
            "echo_requests": lab.count(p, "icmp.type == 8"),
            "printer_mac": replies[0][0] if replies else None,
            "reply_ttl": int(replies[0][1]) if replies else None}


def truth_1_2(p):
    return {"icmp_on_r1_port": lab.count(p, on("sw1:eth1", "icmp")),
            "icmp_on_printer_port": lab.count(p, on("sw1:eth3", "icmp")),
            "arp_on_printer_port": lab.count(p, on("sw1:eth3", "arp"))}


def truth_3_1(p):
    asked = [ip for ip in col(p, f"arp.opcode == 1 && eth.src == {LAPTOP}", "arp.dst.proto_ipv4") if ip != "192.168.1.20"]
    dst = col(p, f"arp.opcode == 1 && eth.src == {LAPTOP}", "eth.dst")
    return {"printer_mac": (col(p, "arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.20", "arp.src.hw_mac") or [None])[0],
            "request_dst_mac": dst[0] if dst else None,
            "asked_for_web": asked[0] if asked else None,
            "gateway_mac": (col(p, "arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.1", "arp.src.hw_mac") or [None])[0]}


def truth_3_2(p):
    claimed = {}
    for ip, hw in lab.fields(p, "arp.opcode == 2 || arp.isgratuitous == 1", "arp.src.proto_ipv4", "arp.src.hw_mac"):
        claimed.setdefault(ip, set()).add(hw)
    dup = [ip for ip, macs in claimed.items() if len(macs) > 1]
    impostors = (claimed.get(dup[0], set()) - {lab.MAC["printer"]}) if dup else set()
    return {"duplicate_ip": dup[0] if dup else None,
            "impostor_mac": sorted(impostors)[0] if impostors else None,
            "gratuitous_mac": (col(p, "arp.isgratuitous == 1", "arp.src.hw_mac") or [None])[0]}


def truth_4_1(p):
    offer = lab.fields(p, "dhcp.option.dhcp == 2", "dhcp.ip.your", "dhcp.option.dhcp_server_id",
                       "dhcp.option.ip_address_lease_time", "dhcp.option.router", "dhcp.option.domain_name_server")
    o = offer[0] if offer else [None] * 5
    return {"offered_ip": o[0], "server_id": o[1], "lease_seconds": int(o[2]) if o[2] else None,
            "router": o[3], "dns_server": o[4], "_kinds": set(col(p, "dhcp", "dhcp.option.dhcp"))}


def truth_4_2(p):
    return {"lan_dst": (col(p, on("sw1:eth1", "dhcp.option.dhcp == 1"), "ip.dst") or [None])[0],
            "relay_dst": (col(p, on("r1:eth2", "dhcp.option.dhcp == 1"), "ip.dst") or [None])[0],
            "giaddr": (col(p, on("r1:eth2", "dhcp.option.dhcp == 1"), "dhcp.ip.relay") or [None])[0],
            "offer_from": (col(p, on("sw1:eth1", "dhcp.option.dhcp == 2"), "ip.src") or [None])[0]}


def truth_5_1(p):
    web = lab.fields(p, 'dns.flags.response == 1 && dns.qry.name == "web.lab" && dns.qry.type == 1', "dns.a", "dns.resp.ttl")
    return {"web_ip": web[0][0].split(",")[0] if web else None,
            "ttl": int(web[0][1].split(",")[0]) if web and web[0][1] else None,
            "cname_target": (col(p, 'dns.flags.response == 1 && dns.qry.name == "intranet.lab"', "dns.cname") or [None])[0],
            "nxdomain_name": (col(p, "dns.flags.rcode == 3", "dns.qry.name") or [None])[0]}


def truth_5_2(p):
    names = col(p, "dns.flags.response == 0", "dns.qry.name")
    rcodes = col(p, 'dns.flags.response == 1 && dns.qry.name == "nas"', "dns.flags.rcode")
    return {"first_name": names[0] if names else None, "queries": len(names),
            "bare_name_rcode": int(rcodes[0]) if rcodes else None}


def truth_6_1(p):
    syn = lab.fields(p, "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 80", "tcp.srcport")
    return {"client_port": int(syn[0][0]) if syn else None,
            "syn_ack_frame": int((col(p, "tcp.flags.syn == 1 && tcp.flags.ack == 1", "frame.number") or [0])[0]) or None,
            "http_status": int((col(p, "http.response", "http.response.code") or [0])[0]) or None,
            "first_fin_from": (col(p, "tcp.flags.fin == 1", "ip.src") or [None])[0]}


def truth_6_2(p):
    rst = lab.fields(p, "tcp.flags.reset == 1", "tcp.stream", "tcp.srcport", "ip.src")
    return {"refused_port": int(rst[0][1]) if rst else None, "refused_stream": int(rst[0][0]) if rst else None,
            "rst_from": rst[0][2] if rst else None}


def truth_7_1(p):
    sh = lab.fields(p, "tls.handshake.type == 2", "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite")
    alpn = col(p, "tls.handshake.type == 1", "tls.handshake.extensions_alpn_str")
    return {"sni": frozenset(col(p, "tls.handshake.type == 1", "tls.handshake.extensions_server_name")) or None,
            "tls_version": norm_tls(sh[0][0] or "0x0303") if sh else None,
            "cipher": norm_int(sh[0][1]) if sh else None,
            "offered_alpn": norm_words(alpn[0]) if alpn else None}


def secret_from(p):
    """What intranet.lab sent, read back by decrypting the capture with the session keys curl saved."""
    keys = p.with_suffix(".keys")
    if not keys.exists():
        return None
    rows = lab.fields(p, "http.response", "http.file_data", opts=("-o", f"tls.keylog_file:{keys}"))
    for row in rows:
        try:
            text = binascii.unhexlify(row[0].replace(":", "")).decode(errors="replace")
        except (binascii.Error, ValueError):
            text = row[0]
        m = re.search(r"the answer is (\S+)", text)
        if m:
            return m.group(1)
    return None


def truth_7_2(p):
    sh = lab.fields(p, "tls.handshake.type == 2", "tls.handshake.version", "tls.handshake.extensions.supported_version")
    cert = lab.fields(p, "tls.handshake.type == 11", "x509sat.printableString", "x509sat.uTF8String")
    names = [n for n in ",".join(sum(cert[:1], [])).split(",") if n] if cert else []
    return {"tls_version": norm_tls((sh[0][1] or sh[0][0])) if sh else None,
            # the certificate lists the issuer first (O, CN), then the subject (O, CN)
            "cert_issuer": next((n for n in names if n.endswith(" CA")), None),
            "cert_cn": next((n for n in names if "." in n), None),
            "secret": secret_from(p)}


def truth_8_1(p):
    senders = col(p, "tcp.analysis.retransmission", "ip.src")
    return {"retransmissions": lab.count(p, "tcp.analysis.retransmission"),
            "retransmitted_by": max(set(senders), key=senders.count) if senders else None,
            "dup_acks": lab.count(p, "tcp.analysis.duplicate_ack")}


def mystery():
    for f in (lab.STATE / "mystery.json", lab.CAPTURES / "8.2.json"):
        if f.exists():
            return json.loads(f.read_text())
    return None


def truth_8_2(p):
    m = mystery()
    return {"broken_router": m["router"] if m else None, "cause": m["cause"] if m else None}


def truth_8_3(p):
    big = lab.fields(p, on("laptop:eth1", f"eth.src == {LAPTOP} && frame.len > 1514"), "frame.len")
    return {"stuck_frame_bytes": int(big[0][0]) if big else None,
            "big_frames_past_switch": lab.count(p, on("sw1:eth1", "frame.len > 1514")),
            "dropped_by": "sw1" if big else None,
            "laptop_mtu": 9000}


def truth(t, pcap):
    return globals()[f"truth_{t.replace('.', '_')}"](pcap)


# ── the tasks ──────────────────────────────────────────────────────────────────
def capture_task(t, questions):
    """The common shape: the capture first, then each answer against what that capture holds."""
    pcap, result = captured(t)
    yield result
    if not pcap:
        return
    want = truth(t, pcap)
    doc = answers(t)
    for key, kind, label, *hint in questions:
        yield ask(doc, key, kind, want.get(key), label, *hint)


def t1_1():
    yield from capture_task("1.1", [
        ("first_protocol", "word", "the protocol of the first frame the laptop sent (follow along)",
         "but the laptop sent something else first. Why couldn't it ping straight away?"),
        ("echo_requests", "int", "how many echo requests the laptop sent (follow along)"),
        ("printer_mac", "mac", "the printer's MAC address, from a reply's Ethernet header (challenge)"),
        ("reply_ttl", "int", "the TTL in the printer's replies (challenge)")])


def t1_2():
    yield from capture_task("1.2", [
        ("icmp_on_r1_port", "int", "ICMP packets seen on r1's port, sw1:eth1 (follow along)",
         "but that's not what the sw1:eth1 frames say. Filter on frame.interface_name."),
        ("icmp_on_printer_port", "int", "ICMP packets seen on the printer's port, sw1:eth3 (challenge)",
         "but the switch only sends a frame where its destination MAC lives. Count again."),
        ("arp_on_printer_port", "int", "ARP packets seen on the printer's port, sw1:eth3 (challenge)")])


# Display filters: each must pick exactly the frames ours picks in pcaps/mixed.pcapng.
DISPLAY = {
    "2.1": [("dns", "dns", "only DNS (follow along)"),
            ("printer", "ip.addr == 192.168.1.20", "everything to or from the printer, 192.168.1.20 (follow along)"),
            ("not_web", "!(ip.addr == 192.168.2.10)", "everything except web's traffic, ARP and STP included (follow along)"),
            ("laptop_dns_or_arp", f"(dns || arp) && eth.src == {LAPTOP}", "DNS or ARP sent by the laptop (challenge)"),
            ("syn_only", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "only the first packet of each TCP connection (challenge)")],
}
CAPFILTER = {
    "2.2": [("bpf_https_web", "host 192.168.2.10 and tcp port 443", "a capture filter: HTTPS to or from web (challenge)"),
            ("bpf_laptop_not_arp", f"ether host {LAPTOP} and not arp",
             "a capture filter: the laptop's frames, but no ARP (challenge)")],
}


def display_filter(doc, key, ours, label):
    given = doc.get(key)
    if blank(given):
        return False, f"{label}: {key} is still blank"
    try:
        theirs = lab.frames(MIXED, given)
    except ValueError as e:
        return False, f"{label}: {given!r} isn't a display filter tshark understands: {e}"
    want = lab.frames(MIXED, ours)
    if theirs == want:
        return True, f"{label}: {given}  ({len(want)} frames)"
    extra, missing = len(set(theirs) - set(want)), len(set(want) - set(theirs))
    tip = ""
    if key == "not_web" and "!=" in given:
        tip = " != only matches frames that have an IP address at all. What about ARP and STP?"
    return False, (f"{label}: {given!r} matches {len(theirs)} frames, the right ones are {len(want)} "
                   f"({extra} too many, {missing} missing).{tip}")


def t2_1():
    if not MIXED.exists():
        yield False, "pcaps/mixed.pcapng is missing: it comes with the lab (git checkout pcaps/)"
        return
    doc = answers("2.1")
    for key, ours, label in DISPLAY["2.1"]:
        yield display_filter(doc, key, ours, label)


def t2_2():
    pcap, result = captured("2.2")
    yield result
    if pcap:
        others = lab.count(pcap, "!(udp.port == 53)")
        yield others == 0, (f"captures/2.2.pcapng holds only DNS: the capture filter kept nothing else (follow along)"
                            if others == 0 else f"captures/2.2.pcapng has {others} frames that aren't DNS. "
                            f'Did you give the capture filter?  {how("2.2")}')
        doc = answers("2.2")
        yield ask(doc, "dns_frames", "int", lab.count(pcap, ""), "how many frames the capture filter kept (follow along)")
    doc = answers("2.2")
    for key, ours, label in CAPFILTER["2.2"]:
        given = doc.get(key)
        if blank(given):
            yield False, f"{label}: {key} is still blank"
            continue
        try:
            theirs = lab.tcpdump_frames(MIXED, given)
        except ValueError as e:
            yield False, f"{label}: {given!r} isn't a capture filter (BPF) tcpdump understands: {e}"
            continue
        want = lab.tcpdump_frames(MIXED, ours)
        yield theirs == want, (f"{label}: {given}  ({len(want)} packets)" if theirs == want else
                               f"{label}: {given!r} keeps {len(theirs)} packets of pcaps/mixed.pcapng, "
                               f"the right ones are {len(want)}")


def t3_1():
    yield from capture_task("3.1", [
        ("printer_mac", "mac", "the printer's MAC address, from its ARP reply (follow along)"),
        ("request_dst_mac", "mac", "where the laptop's ARP request was sent: its destination MAC (follow along)"),
        ("asked_for_web", "ip", "the address the laptop asked ARP about, to reach web (challenge)",
         "but web isn't on the laptop's network. Who does the laptop hand those packets to?"),
        ("gateway_mac", "mac", "that address's MAC, from the reply (challenge)")])


def t3_2():
    yield from capture_task("3.2", [
        ("duplicate_ip", "ip", "the address two computers claimed (follow along)"),
        ("impostor_mac", "mac", "the MAC address that isn't the printer's (follow along)",
         "but that's the printer's own MAC (task 3.1). Which other one answered?"),
        ("gratuitous_mac", "mac", "who sent the gratuitous ARP (challenge)")])


def t4_1():
    pcap, result = captured("4.1")
    yield result
    if not pcap:
        return
    want = truth("4.1", pcap)
    kinds = want.pop("_kinds")
    names = {"1": "Discover", "2": "Offer", "3": "Request", "5": "ACK"}
    missing = [n for k, n in names.items() if k not in kinds]
    yield not missing, ("the capture has all four: Discover, Offer, Request, ACK" if not missing else
                        f"the capture is missing the {', '.join(missing)}. Take it again: {how('4.1')}")
    doc = answers("4.1")
    for key, kind, label in [("offered_ip", "ip", "the address offered to the laptop (follow along)"),
                             ("server_id", "ip", "the DHCP server's identifier, option 54 (follow along)"),
                             ("lease_seconds", "int", "the lease time, in seconds (follow along)"),
                             ("router", "ip", "the router (default gateway) the server hands out (challenge)"),
                             ("dns_server", "ip", "the DNS server it hands out (challenge)")]:
        yield ask(doc, key, kind, want[key], label)


def t4_2():
    yield from capture_task("4.2", [
        ("lan_dst", "ip", "where the laptop sent its Discover, on the home network (follow along)"),
        ("relay_dst", "ip", "where r1 sent that Discover on, towards r2 (follow along)"),
        ("giaddr", "ip", "the relay agent address r1 wrote into it (challenge)",
         "but that's not the Relay agent IP address field. Expand the DHCP layer of r1's copy."),
        ("offer_from", "ip", "who the laptop got its Offer from, at the IP layer (challenge)")])


def t5_1():
    yield from capture_task("5.1", [
        ("web_ip", "ip", "web.lab's address, from the answer (follow along)"),
        ("ttl", "int", "how long that answer may be cached, in seconds (follow along)"),
        ("cname_target", "word", "the name intranet.lab is an alias for (challenge)"),
        ("nxdomain_name", "word", "the name that doesn't exist (challenge)")])


def t5_2():
    yield from capture_task("5.2", [
        ("first_name", "word", "the first name the laptop asked for (follow along)",
         "but that's not the first query. You typed nas: what did the resolver add?"),
        ("queries", "int", "how many queries the one ping caused (follow along)"),
        ("bare_name_rcode", "rcode", "the response code the server gave for plain nas (challenge)")])


def t6_1():
    yield from capture_task("6.1", [
        ("client_port", "int", "the laptop's port for the connection (follow along)"),
        ("syn_ack_frame", "int", "the frame number of the SYN-ACK (follow along)"),
        ("http_status", "int", "the HTTP status code web answered with (challenge)"),
        ("first_fin_from", "ip", "who closed the connection first, sending the first FIN (challenge)")])


def t6_2():
    yield from capture_task("6.2", [
        ("refused_port", "int", "the port that refused the connection (follow along)"),
        ("rst_from", "ip", "who sent the reset (follow along)"),
        ("refused_stream", "int", "the refused connection's stream index, tcp.stream (challenge)")])


def t7_1():
    yield from capture_task("7.1", [
        ("sni", "words", "the server names the laptop asked for, both of them (follow along)"),
        ("tls_version", "tls", "the TLS version the server chose (follow along)",
         "but look at the Server Hello's supported_versions extension, not the record header."),
        ("cipher", "cipher", "the cipher suite the server chose (challenge)"),
        ("offered_alpn", "words", "the application protocols the laptop offered, ALPN (challenge)")])


def t7_2():
    pcap, result = captured("7.2")
    yield result
    if not pcap:
        return
    want = truth("7.2", pcap)
    keys = pcap.with_suffix(".keys")
    yield keys.exists(), (f"captures/7.2.keys: the session keys curl saved" if keys.exists() else
                          f"captures/7.2.keys is missing: the capture command saves it ({how('7.2')})")
    doc = answers("7.2")
    yield ask(doc, "tls_version", "tls", want["tls_version"], "the TLS version this time (follow along)")
    yield ask(doc, "cert_cn", "word", want["cert_cn"], "the name in the server's certificate (follow along)")
    yield ask(doc, "cert_issuer", "word", want["cert_issuer"], "who issued the certificate (follow along)")
    yield ask(doc, "secret", "word", want["secret"] or "gentoo-penguin", "the answer hidden in secret.txt (challenge)",
              "but that's not what the decrypted page says.")


def t8_1():
    pcap, result = captured("8.1")
    yield result
    if not pcap:
        return
    want = truth("8.1", pcap)
    yield want["retransmissions"] > 0, ("the capture has retransmissions: the loss was on" if want["retransmissions"]
                                        else "the capture has no retransmissions. Did you make break X=loss first?")
    doc = answers("8.1")
    yield ask(doc, "retransmissions", "int", want["retransmissions"], "how many retransmissions (follow along)",
              "but that's not the count. Try the filter tcp.analysis.retransmission and read the status bar.")
    yield ask(doc, "retransmitted_by", "ip", want["retransmitted_by"], "who had to send again (follow along)")
    yield ask(doc, "dup_acks", "int", want["dup_acks"], "how many duplicate ACKs (challenge)")


def t8_2():
    pcap, result = captured("8.2")
    yield result
    if not pcap:
        return
    want = truth("8.2", pcap)
    if not want["cause"]:
        yield False, "there's no mystery fault on record. Start it with  make break X=mystery,  then capture"
        return
    doc = answers("8.2")
    yield ask(doc, "broken_router", "word", want["broken_router"], "the router where the packets stop (challenge)",
              "but the packets get past that one. Compare the two capture points.")
    yield ask(doc, "cause", "word", want["cause"], "the cause: acl (a filter drops them) or route (no way back) (challenge)",
              "but that's not it. Did web get the request at all?")


def t8_3():
    pcap, result = captured("8.3")
    yield result
    if not pcap:
        return
    want = truth("8.3", pcap)
    yield bool(want["stuck_frame_bytes"]), ("the capture has the laptop's oversized frames: the fault was on"
                                            if want["stuck_frame_bytes"] else
                                            "the laptop sent no frame bigger than 1514 bytes. Did you make break X=mtu first?")
    doc = answers("8.3")
    yield ask(doc, "stuck_frame_bytes", "int", want["stuck_frame_bytes"], "the size of the frame that never got an answer (follow along)")
    yield ask(doc, "big_frames_past_switch", "int", want["big_frames_past_switch"], "how many of them reached r1's side of the switch (follow along)")
    yield ask(doc, "dropped_by", "word", want["dropped_by"], "the box that dropped them (challenge)")
    yield ask(doc, "laptop_mtu", "int", want["laptop_mtu"], "the laptop's MTU, the cause (challenge)",
              "but that's not what ip link says on the laptop.")


TASKS = {
    "1.1": "your first capture", "1.2": "where you capture",
    "2.1": "display filters", "2.2": "capture filters",
    "3.1": "who has?", "3.2": "two answers",
    "4.1": "DORA", "4.2": "the relay",
    "5.1": "names and answers", "5.2": "the search domain",
    "6.1": "a whole connection", "6.2": "refused",
    "7.1": "what TLS shows", "7.2": "decrypt your own",
    "8.1": "loss", "8.2": "the mystery fault", "8.3": "the black hole",
}
CHAPTERS = {1: "what a capture shows", 2: "filters", 3: "ARP", 4: "DHCP", 5: "DNS", 6: "TCP", 7: "TLS",
            8: "a broken path"}


def report(t):
    print(f"{C['c']}╭─{C['x']} {C['b']}task {t}{C['x']} {C['d']}·{C['x']} {TASKS[t]}", flush=True)
    results = []
    try:
        for ok, msg in globals()[f"t{t.replace('.', '_')}"]():
            ok = bool(ok)
            results.append(ok)
            print(f"{C['c']}│{C['x']}  {C['g'] + '✓' if ok else C['r'] + '✗'}{C['x']} {msg}", flush=True)
    except Exception as e:  # a half-finished task shouldn't crash the checker
        results.append(False)
        print(f"{C['c']}│{C['x']}  {C['r']}✗{C['x']} {str(e).splitlines()[0][:160] if str(e) else type(e).__name__}")
    passed = sum(results)
    done = passed == len(results)
    tail = (f"{C['g']}verified{C['x']}" if done else
            f"{C['y']}stuck?{C['x']} the hints and the answer are on the guide page  "
            f"{C['d']}{GUIDE}/task-{t.replace('.', '-')}/{C['x']}")
    print(f"{C['c']}╰─{C['x']} {passed}/{len(results)} checks passed  {tail}\n")
    return done


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    if arg.startswith("ch"):
        n = int(arg[2:])
        print(f"{C['b']}chapter {n} · {CHAPTERS.get(n, '')}{C['x']}\n")
        sys.exit(0 if all([report(t) for t in TASKS if t.startswith(f"{n}.")]) else 1)
    if arg == "all":
        done = [t for t in TASKS if report(t)]
        print(f"{C['b']}{len(done)}/{len(TASKS)} tasks verified{C['x']}")
        sys.exit(0 if len(done) == len(TASKS) else 1)
    if arg not in TASKS:
        sys.exit(f"no task {arg}: tasks are {', '.join(TASKS)}")
    sys.exit(0 if report(arg) else 1)
