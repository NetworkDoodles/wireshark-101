"""Helpers the capture, traffic, checker and status scripts share: run a command on a lab node, configure a
router, and read a capture with tshark."""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOPO = ROOT / "lab" / "topology.clab.yml"
CAPTURES = ROOT / "captures"
PCAPS = ROOT / "pcaps"            # reference captures, made from this lab (.maint/make_pcaps.sh)
STATE = ROOT / "lab" / ".state"   # what make break did, for the checker (never committed)
SHARK = "nd-shark:1"
HOSTS = ["laptop", "printer", "broken-pc", "web", "dns"]
NETWORK = ["sw1", "r1", "r2"]     # CapeOS Bolt: an IOS-style CLI
MAC = {"laptop": "aa:aa:aa:11:11:11", "printer": "aa:aa:aa:22:22:22", "broken-pc": "aa:aa:aa:33:33:33",
       "web": "aa:aa:aa:44:44:44", "dns": "aa:aa:aa:55:55:55"}
IP = {"laptop": None, "printer": "192.168.1.20", "broken-pc": "192.168.1.30", "web": "192.168.2.10",
      "dns": "192.168.2.53", "r1": "192.168.1.1"}


def sh(node, cmd, timeout=30):
    """Run a shell command on a host; return (exit code, output)."""
    try:
        p = subprocess.run(["docker", "exec", node, "sh", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as e:
        return 127, str(e)


def show(node, cmd, timeout=20):
    """Run a CLI command on the switch or a router; return its output ('' if it can't)."""
    try:
        p = subprocess.run(["docker", "exec", "-i", node, "capeos-cli", "-c", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def config(node, *lines):
    """Type configuration commands on the switch or a router, as you would: configure terminal ... end."""
    text = "\n".join(["configure terminal", *lines, "end", ""])
    p = subprocess.run(["docker", "exec", "-i", node, "capeos-cli"], input=text, capture_output=True, text=True,
                       timeout=30)
    return p.stdout


def running(node):
    p = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", node], capture_output=True, text=True)
    return p.stdout.strip() == "true"


def ready(node):
    if not running(node):
        return False
    if node in NETWORK:
        return sh(node, "test -e /run/capeos/ready")[0] == 0
    return True


def addr(node, dev="eth1"):
    """A host's IPv4 address and prefix on eth1, like '192.168.1.20/24' (or None)."""
    code, out = sh(node, f"ip -4 -o addr show dev {dev}")
    for word in out.split():
        if "/" in word and word[0].isdigit():
            return word
    return None


def mac(node, dev="eth1"):
    code, out = sh(node, f"cat /sys/class/net/{dev}/address")
    return out.lower() if code == 0 else None


# ── tshark, from the lab's tool image (tshark 4.6, the same dissectors as desktop Wireshark) ─────────────
def tshark(*args, timeout=60):
    """Run tshark on files in this repo; return (exit code, stdout, stderr)."""
    uid = f"{os.getuid()}:{os.getgid()}"
    cmd = ["docker", "run", "--rm", "-i", "-u", uid, "-v", f"{ROOT}:{ROOT}", "-w", str(ROOT), SHARK, *map(str, args)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "tshark timed out"


def _tool(tool, *args, timeout=60):
    uid = f"{os.getuid()}:{os.getgid()}"
    cmd = ["docker", "run", "--rm", "-u", uid, "-v", f"{ROOT}:{ROOT}", "-w", str(ROOT), "--entrypoint", tool, SHARK,
           *map(str, args)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def tcpdump_frames(pcap, bpf):
    """The timestamps of the packets a capture filter (BPF) keeps, read back from a file.
    tcpdump applies a capture filter to a saved file exactly as it would on the wire."""
    p = _tool("tcpdump", "-nn", "--nano", "-tt", "-r", pcap, bpf)
    if p.returncode != 0:
        raise ValueError(p.stderr.strip().splitlines()[-1] if p.stderr.strip() else "tcpdump failed")
    return {line.split()[0] for line in p.stdout.splitlines() if line.strip()}


def bpf_keep(pcap, bpf):
    """The frame numbers a capture filter keeps."""
    keep = tcpdump_frames(pcap, bpf)
    return [int(n) for n, ts in fields(pcap, "", "frame.number", "frame.time_epoch") if ts in keep]


def keep_frames(src, dst, numbers):
    """Write only these frames of src to dst, as pcapng (the interface names stay)."""
    args = ["-F", "pcapng", "-r", src, dst, *map(str, numbers)] if numbers else ["-F", "pcapng", "-r", src, dst, "0"]
    p = _tool("editcap", *args)
    if p.returncode != 0:
        raise ValueError(p.stderr.strip() or "editcap failed")


def interfaces(pcap):
    """The ports a capture was taken on, from the file's interface list (even ports that saw nothing)."""
    p = _tool("capinfos", "-I", pcap)
    return {line.split("=", 1)[1].strip() for line in p.stdout.splitlines() if line.strip().startswith("Name =")}


def fields(pcap, display_filter, *names, opts=()):
    """Rows of field values for the frames a display filter matches. Each row is a list of strings, one per
    field ('' when a frame doesn't have it; several values of one field are joined with commas)."""
    args = ["-r", pcap, "-n", *opts, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "aggregator=,"]
    if display_filter:
        args += ["-Y", display_filter]
    for n in names:
        args += ["-e", n]
    code, out, err = tshark(*args)
    if code != 0:
        # tshark explains a bad filter on its first line ("tshark: ... was unexpected"), then draws a caret.
        lines = [l for l in err.splitlines() if l.strip()]
        why = next((l.removeprefix("tshark: ") for l in lines if l.startswith("tshark:")), lines[0] if lines else "")
        raise ValueError(why or f"tshark failed on {pcap}")
    return [line.split("\t") for line in out.splitlines()]


def first(pcap, display_filter, name, opts=()):
    rows = fields(pcap, display_filter, name, opts=opts)
    return rows[0][0] if rows else None


def count(pcap, display_filter):
    return len(fields(pcap, display_filter, "frame.number"))


def frames(pcap, display_filter):
    """The frame numbers a display filter matches. Raises ValueError if the filter doesn't compile."""
    return [int(r[0]) for r in fields(pcap, display_filter, "frame.number")]


def capture_file(name):
    p = CAPTURES / f"{name}.pcapng"
    return p if p.exists() else None
