"""make capture · record what crosses one or more ports into captures/<NAME>.pcapng.

    make capture AT=laptop:eth1 NAME=1.1 X=ping          capture while the lab sends some traffic
    make capture AT=laptop:eth1 NAME=mine FOR=30s        capture for 30 seconds while you do things yourself
    make capture AT=sw1:eth1,sw1:eth3 NAME=1.2 X=crossping   two ports into one file
    make capture AT=laptop:eth1 NAME=2.2 X=mixed F="udp port 53"   keep only what a capture filter lets through

AT is one or more node:port pairs, comma separated (make ports lists every port you can capture).
The capturing is done by `containerlab capture`, from outside the nodes: like a tap on the cable.
"""
import argparse
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, pathlib.Path(__file__).resolve().parent.as_posix())
import lab  # noqa: E402


def clab():
    """containerlab needs root to open the ports; in the dev container sudo needs no password."""
    return ["containerlab"] if os.geteuid() == 0 else ["sudo", "-n", "containerlab"]


def targets(at):
    """'laptop:eth1,sw1:eth1,sw1:eth3' → ['--target', 'laptop:eth1', '--target', 'sw1:eth1,eth3']"""
    by_node = {}
    for item in at.replace(" ", ",").split(","):
        if not item:
            continue
        if ":" not in item:
            # A bare interface name belongs to the node before it: sw1:eth1,eth3
            if not by_node:
                sys.exit(f"AT={at}: write each port as node:port, like laptop:eth1")
            by_node[list(by_node)[-1]].append(item)
            continue
        node, port = item.split(":", 1)
        by_node.setdefault(node, []).append(port)
    out = []
    for node, ports in by_node.items():
        out += ["--target", f"{node}:{','.join(ports)}"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--at", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--x", default="")
    ap.add_argument("--for", dest="duration", default="")
    ap.add_argument("--filter", default="")
    a = ap.parse_args()

    lab.CAPTURES.mkdir(exist_ok=True)
    out = lab.CAPTURES / f"{a.name}.pcapng"
    tmp = lab.CAPTURES / f".{a.name}.raw.pcapng"
    duration = a.duration or ("" if a.x else "20s")
    cmd = clab() + ["capture", "-t", str(lab.TOPO), *targets(a.at), "-w", str(tmp)]
    if duration:
        cmd += ["--duration", duration]
    where = ", ".join(t for t in targets(a.at) if t != "--target")
    print(f"\n  capturing on {where}" + (f" for {duration}" if duration else "") +
          (f", keeping only: {a.filter}" if a.filter else "") + f"  →  captures/{out.name}\n", flush=True)

    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    if a.x:
        time.sleep(1.5)                       # let the capture open every port before the traffic starts
        if proc.poll() is not None:
            sys.exit("the capture didn't start:\n" + proc.stderr.read())
        subprocess.run([sys.executable, str(lab.ROOT / "lab" / "traffic.py"), a.x, f"--keys={a.name}"])
        time.sleep(1.5)                       # the last answers are still on their way
        proc.send_signal(signal.SIGINT)
    else:
        print("  do your thing now (make shell H=laptop, in another terminal); Ctrl+C stops early\n", flush=True)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)
    try:
        _, err = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    if proc.returncode not in (0, -signal.SIGINT) or not tmp.exists():
        sys.exit("the capture failed:\n" + (err or "").strip())

    if os.geteuid() != 0:                     # containerlab ran as root: hand the file back to you
        subprocess.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(tmp)], check=False)
    if a.filter:
        # A capture filter decides what gets saved at all. tcpdump applies one to the stream exactly as it
        # would on the wire; whatever it drops is never written down.
        try:
            lab.keep_frames(tmp, out, lab.bpf_keep(tmp, a.filter))
        except ValueError as e:
            sys.exit(f"that capture filter didn't work: {e}")
        finally:
            tmp.unlink(missing_ok=True)
    else:
        shutil.move(tmp, out)
    n = lab.count(out, "")
    print(f"\n  saved {n} frames to captures/{out.name}")
    print("  open it: in the browser Wireshark (make wireshark), or right-click it in the Explorer → Download,")
    print(f"  or read it here:  tshark -r captures/{out.name}\n")


if __name__ == "__main__":
    main()
