#!/bin/sh
# Sets a host up when the lab starts (containerlab runs `start <role>` on each host).
# The hosts have no management port: eth1 is their only network card, as on a real computer.
set -e
# IPv4 only, as in Networking 101: no IPv6 packets to read past in the captures.
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
# containerlab gives the card a second, internal name; a real computer's card has just the one.
for a in $(ip -o link show eth1 | grep -o 'altname [^ ]*' | cut -d' ' -f2); do ip link property del dev eth1 altname "$a"; done
# The NIC offloads (TSO/GSO/GRO) would hand the capture 60 KB "packets" no wire could carry. Off, so what
# you see is what a real cable carries.
ethtool -K eth1 tso off gso off gro off 2>/dev/null || true
ip link set eth1 up
case "$1" in
  laptop)
    # A DHCP client, as on any laptop: it asks for an address now and renews the lease on its own.
    udhcpc -i eth1 -b -p /run/udhcpc.pid -x hostname:laptop >/var/log/udhcpc.log 2>&1
    ;;
  printer)
    ip addr add 192.168.1.20/24 dev eth1
    ip route add default via 192.168.1.1
    echo "nameserver 192.168.2.53" > /etc/resolv.conf
    ;;
  broken-pc)
    # In this lab broken-pc is set up right; chapter 3 has it claim the printer's address for a moment.
    ip addr add 192.168.1.30/24 dev eth1
    ip route add default via 192.168.1.1
    echo "nameserver 192.168.2.53" > /etc/resolv.conf
    ;;
  web)
    ip addr add 192.168.2.10/28 dev eth1
    ip route add default via 192.168.2.1
    echo "nameserver 192.168.2.53" > /etc/resolv.conf
    mkdir -p /srv/www /srv/intranet
    echo "Hello from web.lab, 192.168.2.10" > /srv/www/index.html
    # A bigger file, so a download takes enough packets to watch TCP work (chapter 8).
    head -c 2000000 /dev/urandom > /srv/www/big.bin
    echo "Hello from intranet.lab. Only someone who decrypted the TLS can read this line: the answer is gentoo-penguin" \
        > /srv/intranet/secret.txt
    echo "intranet.lab: nothing to see here, try /secret.txt" > /srv/intranet/index.html
    nginx
    ;;
  dns)
    ip addr add 192.168.2.53/28 dev eth1
    ip route add default via 192.168.2.49
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    # DNS for the lab's names, from the files in /etc/lab-dns (lab/dns/ in the repo), re-read on change.
    # DHCP for the home network, two hops away: r1 relays the laptop's requests here (ip helper-address).
    # dnsmasq picks the range by the relay's address in the request (giaddr), 192.168.1.1.
    dnsmasq --no-resolv --no-hosts --hostsdir=/etc/lab-dns --domain=lab --local=/lab/ --interface=eth1 --local-ttl=60 \
            --cname=intranet.lab,web.lab \
            --dhcp-range=192.168.1.100,192.168.1.199,255.255.255.0,10m \
            --dhcp-option=option:router,192.168.1.1 --dhcp-option=option:dns-server,192.168.2.53 \
            --dhcp-option=option:domain-name,lab --dhcp-authoritative --no-ping \
            --log-queries --log-dhcp --log-facility=/var/log/dnsmasq.log
    ;;
esac
