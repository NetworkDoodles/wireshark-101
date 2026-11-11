"""make solve T=1.2 · make skip T=1.2 · make break X=loss · make fix

solve: stuck? This takes the task's capture for you on the running lab, exactly as the guide does, then fills
       in that task's answers file from it. It prints every step, so you can read them.
skip:  no lab, or no time? This copies the reference capture from pcaps/ into captures/ and fills in the
       answers from it. Nothing needs to be running.
break: chapter 8's faults, on purpose:  loss (packets go missing between the routers), mystery (one of three
       faults, picked at random: your job to find), mtu (the laptop's MTU set wrong).
fix:   undoes every fault.
"""
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys

sys.path.insert(0, pathlib.Path(__file__).resolve().parent.as_posix())
import lab  # noqa: E402

sys.path.insert(0, (lab.ROOT / "checks").as_posix())
import check  # noqa: E402

ANSWERS = lab.ROOT / "answers"
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def say(where, what):
    print(f"  {where:<10} {what}", flush=True)


def configure(node, *lines):
    for line in ("configure terminal", *lines, "end"):
        say(node, line)
    lab.config(node, *lines)


def clab(*args):
    cmd = (["containerlab"] if os.geteuid() == 0 else ["sudo", "-n", "containerlab"]) + list(args)
    say("host", " ".join(["containerlab", *args]))
    subprocess.run(cmd, capture_output=True, text=True)


def shown(key, value):
    """An answer the way you'd write it in the file."""
    if isinstance(value, frozenset):
        return ", ".join(sorted(value))
    if key == "cipher" and isinstance(value, int):
        return f"0x{value:04x}"
    if key.endswith("rcode") and isinstance(value, int):
        return RCODES.get(value, value)
    return value


def fill(task, values):
    """Write values into answers/<task>.yml after their keys, keeping every comment."""
    path = ANSWERS / f"{task}.yml"
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        key = line.split(":")[0].strip()
        if key in values and not line.lstrip().startswith("#") and values[key] is not None:
            comment = line.partition(":")[2].partition(" #")[2]
            text = f"{key}: {shown(key, values[key])}"
            lines[i] = f"{text:<28} #{comment}" if comment else text
    path.write_text("\n".join(lines) + "\n")
    say("answers", f"filled in answers/{task}.yml")


def capture(task):
    at, x, _ = check.CAPTURE[task]
    say("host", check.how(task))
    args = [sys.executable, str(lab.ROOT / "lab" / "capture.py"), "--at", at, "--name", task, "--x", x]
    if task in check.FILTER:
        args += ["--filter", check.FILTER[task]]
    subprocess.run(args, check=True)


def answer_from(task, pcap):
    if task == "2.2":
        values = {"dns_frames": lab.count(pcap, "")} | {k: ours for k, ours, _ in check.CAPFILTER["2.2"]}
    else:
        values = check.truth(task, pcap)
        values.pop("_kinds", None)
    if task == "7.2" and not values.get("secret"):
        values["secret"] = "gentoo-penguin"
    fill(task, values)


# ── the faults (chapter 8) ─────────────────────────────────────────────────────
MYSTERIES = [
    {"router": "r1", "cause": "acl"},     # r1 drops web traffic arriving from the home network
    {"router": "r2", "cause": "acl"},     # r2 drops web traffic arriving from r1
    {"router": "r2", "cause": "route"},   # r2 has lost its route back to the home network
]


def acl(node, port):
    configure(node, "ip access-list extended NO-WEB", " deny tcp any host 192.168.2.10 eq 80",
              " deny tcp any host 192.168.2.10 eq 443", " permit ip any any", " exit",
              f"interface {port}", " no ip unreachables", " ip access-group NO-WEB in")
    # no ip unreachables: drop silently. CapeOS 0.11.0+ (like the reference) otherwise answers a deny with
    # ICMP administratively prohibited; 0.10.0 accepts the line and drops silently either way.


def break_loss():
    clab("tools", "netem", "set", "-t", str(lab.TOPO), "-n", "r2", "-i", "eth1", "--loss", "3")
    print("\n  r2 now loses 3% of what it sends towards r1. Downloads still work, slowly. Capture one.\n")


def break_mystery():
    lab.STATE.mkdir(exist_ok=True)
    m = random.choice(MYSTERIES)
    (lab.STATE / "mystery.json").write_text(json.dumps(m))
    if m["cause"] == "acl":
        acl(m["router"], "GigabitEthernet1")
    else:
        configure("r2", "no ip route 192.168.1.0 255.255.255.0 10.0.0.1")
    print("\n  Something between the laptop and web is broken now, and the commands above are not your clue:")
    print("  scroll them away. From the laptop, http://web.lab/ doesn't load. Find out where, and why.\n")


def break_mtu():
    for host in ("laptop", "web"):
        say(host, "ip link set eth1 mtu 9000")
        lab.sh(host, "ip link set eth1 mtu 9000")
    print("\n  Someone turned on jumbo frames on the laptop and on web, but not on the network between them.")
    print("  Ping still works. Try https://web.lab/.\n")


def fix():
    clab("tools", "netem", "reset", "-t", str(lab.TOPO), "-n", "r2", "-i", "eth1")
    for node in ("r1", "r2"):
        if "NO-WEB" in lab.show(node, "show running-config"):
            configure(node, "interface GigabitEthernet1", " no ip access-group NO-WEB in", " ip unreachables", " exit",
                      "no ip access-list extended NO-WEB")
    if "ip route 192.168.1.0 255.255.255.0 10.0.0.1" not in lab.show("r2", "show running-config"):
        configure("r2", "ip route 192.168.1.0 255.255.255.0 10.0.0.1")
    for host in ("laptop", "web"):
        say(host, "ip link set eth1 mtu 1500")
        lab.sh(host, "ip link set eth1 mtu 1500")
    state = lab.STATE / "mystery.json"
    if state.exists():
        # The checker still needs to know which fault it was, after it's gone.
        lab.CAPTURES.mkdir(exist_ok=True)
        shutil.move(state, lab.CAPTURES / "8.2.json")
    print("\n  every fault is undone.\n")


BREAK = {"8.1": break_loss, "8.2": break_mystery, "8.3": break_mtu}


# ── solve and skip ─────────────────────────────────────────────────────────────
def solve(task):
    if task == "2.1":
        fill("2.1", {k: ours for k, ours, _ in check.DISPLAY["2.1"]})
        return
    if not lab.ready("laptop"):
        sys.exit("  the lab isn't running. make up starts it, or make skip T=" + task + " uses the reference capture")
    if task in BREAK and not (task == "8.2" and (lab.STATE / "mystery.json").exists()):
        BREAK[task]()
    capture(task)
    if task == "8.2":
        shutil.copy(lab.STATE / "mystery.json", lab.CAPTURES / "8.2.json")
    answer_from(task, lab.capture_file(task))
    if task in BREAK:
        fix()


def skip(task):
    if task == "2.1":
        fill("2.1", {k: ours for k, ours, _ in check.DISPLAY["2.1"]})
        return
    lab.CAPTURES.mkdir(exist_ok=True)
    for ext in (".pcapng", ".keys", ".json"):
        src = lab.PCAPS / f"{task}{ext}"
        if src.exists():
            shutil.copy(src, lab.CAPTURES / src.name)
            say("file", f"copied pcaps/{src.name} to captures/")
    if task == "8.2":
        (lab.STATE / "mystery.json").unlink(missing_ok=True)   # the reference capture's fault, not a live one
    answer_from(task, lab.capture_file(task))


if __name__ == "__main__":
    action = sys.argv[1]
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    if action == "fix":
        fix()
        sys.exit(0)
    if action == "break":
        fn = {"loss": break_loss, "mystery": break_mystery, "mtu": break_mtu}.get(arg)
        if not fn:
            sys.exit("make break X=loss · X=mystery · X=mtu")
        fn()
        sys.exit(0)
    if arg not in check.TASKS:
        sys.exit(f"no task {arg}: tasks are {', '.join(check.TASKS)}")
    print(f"\n  {action} task {arg}:\n")
    {"solve": solve, "skip": skip}[action](arg)
    print(f"\n  done. Now: make check T={arg}\n")
