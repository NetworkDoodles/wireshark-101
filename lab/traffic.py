"""make traffic X=<what> · the lab's scripted traffic, the same every time.

Each kind of traffic is something a real person does on the laptop (ping the printer, open a web page) or a
moment the lab sets up on purpose (two hosts claiming one address). It prints every command it runs, so you
can type them yourself next time:  make shell H=laptop.

    python lab/traffic.py ping        python lab/traffic.py --list
"""
import pathlib
import sys
import time

sys.path.insert(0, pathlib.Path(__file__).resolve().parent.as_posix())
import lab  # noqa: E402

QUIET = "--quiet" in sys.argv
DIM, END = ("\033[2m", "\033[0m") if sys.stdout.isatty() else ("", "")


def run(node, cmd, timeout=60, show=True):
    """Run a command on a host and print it, with the first lines of what it printed (dimmed)."""
    if not QUIET:
        print(f"  {node:<10} {cmd}", flush=True)
    code, out = lab.sh(node, cmd, timeout=timeout)
    if show and out and not QUIET:
        lines = out.splitlines()
        for line in lines[:6]:
            print(f"  {'':<10} {DIM}{line[:110]}{END}")
        if len(lines) > 6:
            print(f"  {'':<10} {DIM}... ({len(lines) - 6} more lines){END}")
    return code, out


def forget_neighbours(node="laptop"):
    """Empty a host's ARP table, so its next packet has to ask ARP first."""
    run(node, "ip neigh flush dev eth1")


def x_ping():
    """the laptop pings the printer, four times"""
    forget_neighbours()
    run("laptop", "ping -c 4 -i 0.3 192.168.1.20")


def x_crossping():
    """the laptop pings web, on another network, three times"""
    forget_neighbours()
    run("laptop", "ping -c 3 -i 0.3 192.168.2.10")


def x_arp():
    """the laptop reaches the printer, then web (two ARP stories)"""
    forget_neighbours()
    run("laptop", "ping -c 2 -i 0.3 192.168.1.20")
    run("laptop", "ping -c 2 -i 0.3 192.168.2.10")


def x_dupip():
    """broken-pc claims the printer's address for a moment, then the laptop looks for the printer"""
    forget_neighbours()
    run("broken-pc", "ip addr add 192.168.1.20/24 dev eth1")
    run("broken-pc", "arping -U -c 1 -I eth1 192.168.1.20")       # "192.168.1.20 is me now" (gratuitous)
    time.sleep(0.5)
    run("laptop", "ping -c 2 -i 0.3 192.168.1.20")
    run("broken-pc", "ip addr del 192.168.1.20/24 dev eth1")


def x_dhcp():
    """the laptop gives its address back and asks for a new one (release, then the four DHCP messages)"""
    run("laptop", "kill -USR2 $(cat /run/udhcpc.pid)")      # release the lease
    time.sleep(1)
    run("laptop", "kill $(cat /run/udhcpc.pid); sleep 0.5")
    run("laptop", "udhcpc -i eth1 -b -p /run/udhcpc.pid -x hostname:laptop >>/var/log/udhcpc.log 2>&1")
    for _ in range(40):
        if lab.addr("laptop"):
            break
        time.sleep(0.25)
    time.sleep(0.5)


def x_dns():
    """the laptop looks up three names: one that exists, an alias, and one that doesn't"""
    run("laptop", "dig +tries=1 +time=2 +noall +answer +comments web.lab")
    run("laptop", "dig +tries=1 +time=2 +noall +answer +comments intranet.lab")
    run("laptop", "dig +tries=1 +time=2 +noall +answer +comments nas.lab")


def x_search():
    """the laptop pings a short name, nas, and lets the system's resolver look it up"""
    run("laptop", "cat /etc/resolv.conf")
    run("laptop", "ping -c 1 -W 1 nas")


def x_web():
    """the laptop opens http://web.lab/"""
    run("laptop", "curl -s --max-time 8 http://web.lab/")


def x_webip():
    """the laptop opens http://192.168.2.10/, by its address (so a DNS problem can't get in the way)"""
    run("laptop", "curl -s --max-time 8 http://192.168.2.10/")


def x_refused():
    """the laptop opens http://web.lab/, then tries a port nothing listens on, then opens the page again"""
    run("laptop", "curl -s --max-time 8 http://web.lab/")
    run("laptop", "curl -s --max-time 3 http://web.lab:8080/")
    run("laptop", "curl -s --max-time 8 http://web.lab/")


def x_tls():
    """the laptop opens https://web.lab/ and https://intranet.lab/"""
    run("laptop", "curl -s --max-time 8 https://web.lab/")
    run("laptop", "curl -s --max-time 8 https://intranet.lab/")


def x_tls12():
    """the laptop fetches https://intranet.lab/secret.txt over TLS 1.2, saving its session keys"""
    run("laptop", "rm -f /tmp/keys.log")
    run("laptop", "SSLKEYLOGFILE=/tmp/keys.log curl -s --max-time 8 --tls-max 1.2 -o /dev/null https://intranet.lab/secret.txt")
    name = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--keys=")), "")
    if name:
        code, keys = lab.sh("laptop", "cat /tmp/keys.log")
        out = lab.CAPTURES / f"{name}.keys"
        out.write_text(keys + "\n")
        if not QUIET:
            print(f"  {'saved':<10} the session keys to {out.relative_to(lab.ROOT)}")


def x_big():
    """the laptop downloads a 2 MB file from web"""
    run("laptop", "curl -s -o /dev/null --max-time 40 -w 'got %{size_download} bytes in %{time_total}s\\n' "
                  "http://web.lab/big.bin", timeout=60)


def x_mixed():
    """a bit of everything, from the laptop and the printer to the servers: ARP, DNS, ping, HTTP and HTTPS"""
    forget_neighbours()
    forget_neighbours("printer")
    run("laptop", "ping -c 2 -i 0.3 192.168.2.53")
    run("laptop", "dig +tries=1 +time=2 +noall +answer +comments web.lab")
    run("printer", "ping -c 2 -i 0.3 192.168.2.53")
    run("laptop", "curl -s --max-time 8 http://web.lab/")
    run("printer", "dig +tries=1 +time=2 +noall +answer +comments printer.lab")
    run("laptop", "curl -s --max-time 8 https://web.lab/")
    run("laptop", "ping -c 2 -i 0.3 192.168.2.10")


KINDS = {k[2:]: f for k, f in globals().items() if k.startswith("x_")}

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--list" in sys.argv or not args:
        print("make traffic X=<one of these>:\n")
        for k, f in KINDS.items():
            print(f"  {k:<10} {f.__doc__}")
        sys.exit(0 if "--list" in sys.argv else 2)
    if args[0] not in KINDS:
        sys.exit(f"no traffic called {args[0]!r}: make traffic lists them")
    if not lab.ready("laptop"):
        sys.exit("the laptop isn't running: is the lab up? (make status, make up)")
    KINDS[args[0]]()
