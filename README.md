# Wireshark 101

**[▶ Open the lab](https://labs.networkdoodles.com/open/wireshark-101)**: one click, nothing to install

The hands-on lab for [Wireshark 101](https://networkdoodles.com/lessons/wireshark-101/). You capture real
traffic on a small network (a laptop asking for an address, looking up a name, opening a web page), open it
in Wireshark, and read what the protocols from [Networking 101](https://networkdoodles.com/lessons/networking-101/)
actually put on the wire: ARP, DHCP, DNS, TCP, TLS. The last chapter breaks the network three ways and you
find out where and why, from the packets alone.

**The guide:** https://networkdoodles.com/labs/wireshark-101/

```
  laptop ────┐
  printer ───┼── sw1 ── r1 ════ 10.0.0.0/30 ════ r2 ──┬── web  192.168.2.10/28   HTTP and HTTPS
  broken-pc ─┘     192.168.1.0/24                     └── dns  192.168.2.53/28   DNS and DHCP
```

## Start

**Open the lab** (the link above, or the button on the [guide's page](https://networkdoodles.com/labs/wireshark-101/)) and
sign in with GitHub. It creates your own codespace, on your GitHub account's free allowance, and opens the lab
app: the guide on the left, VS Code on the right, and Wireshark in a tab of its own. The first start takes a few minutes; the top bar says
**network up** when it's ready. Then follow [task 1.1](https://networkdoodles.com/labs/wireshark-101/task-1-1/):
**Check task**, under the guide, checks your work.

On your own laptop instead: open the repo in its dev container (VS Code's *Reopen in Container*, or
`npx @devcontainers/cli up --workspace-folder .`), then the lab app is at http://localhost:8000.

## Commands

| Command | What it does |
|---|---|
| `make capture AT=laptop:eth1 NAME=1.1 X=ping` | capture on a port (or several, comma separated) while the lab sends some traffic, into `captures/1.1.pcapng` |
| `make ports` | every port you can capture on, and what's at the other end of its cable |
| `make traffic` | the kinds of traffic the lab can send (`X=` above) |
| `make wireshark` | Wireshark in your browser, with `captures/` and `pcaps/` in File › Open |
| `tshark -r captures/1.1.pcapng` | the same capture in the terminal (Wireshark's command-line twin) |
| `make check T=1.1` | check a task (`CH=1` checks a chapter, nothing checks them all) |
| `make solve T=1.1` | stuck? takes the task's capture and fills in its answers, printing every step |
| `make skip T=1.1` | no lab running? uses the reference capture from `pcaps/` instead |
| `make break X=loss` · `make fix` | chapter 8's faults: `loss`, `mystery`, `mtu` |
| `make shell H=laptop` | log in to a node |
| `make help` | everything else |

## How the capturing works

There's no screen in a codespace, so Wireshark can't open a window there. Instead:

- **Capturing** is done by `containerlab capture`, from outside the nodes: like a tap on a cable. It writes
  ordinary pcapng files into `captures/`.
- **Reading** happens in Wireshark served to your browser (`make wireshark`, a
  [linuxserver.io](https://github.com/linuxserver/docker-wireshark) image), in your own Wireshark (right-click a
  file in the Explorer › **Download**), or with `tshark` in the terminal.

The forwarded Wireshark port is private to you: Codespaces asks for your GitHub sign-in. Keep it private,
because the Wireshark page has no password of its own.

The switch and routers run CapeOS Bolt, a lab network OS with an IOS-style CLI. The hosts are small Alpine Linux
containers. `pcaps/` holds reference captures taken from this same lab, so every task also works without it.
