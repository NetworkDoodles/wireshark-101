"""Maintainers: write the blank answers files (the starter state of answers/). Run from the repo root.
Overwrites answers/*.yml, so only run it on a branch where nobody's answers live."""
import pathlib

G = "https://networkdoodles.com/labs/wireshark-101"
A = {
    "1.1": ("your first capture", "make capture AT=laptop:eth1 NAME=1.1 X=ping", [
        ("Follow along", ["first_protocol:     # the protocol of the first frame the laptop sent, like ICMP",
                          "echo_requests:      # how many echo (ping) requests"]),
        ("Challenge", ["printer_mac:        # from the Ethernet header of a reply",
                       "reply_ttl:          # the TTL in the printer's replies"])]),
    "1.2": ("where you capture", "make capture AT=sw1:eth1,sw1:eth3 NAME=1.2 X=crossping", [
        ("Follow along", ["icmp_on_r1_port:       # ICMP packets in the sw1:eth1 frames"]),
        ("Challenge", ["icmp_on_printer_port:  # ICMP packets in the sw1:eth3 frames",
                       "arp_on_printer_port:   # ARP packets in the sw1:eth3 frames"])]),
    "2.1": ("display filters", "nothing to capture: try each filter on pcaps/mixed.pcapng", [
        ("Follow along: a display filter after each colon, no quotes needed", ["dns:", "printer:", "not_web:"]),
        ("Challenge", ["laptop_dns_or_arp:", "syn_only:"])]),
    "2.2": ("capture filters", 'make capture AT=laptop:eth1 NAME=2.2 X=mixed F="udp port 53"', [
        ("Follow along", ["dns_frames:           # how many frames the capture filter kept"]),
        ("Challenge: a capture filter (BPF) after each colon", ["bpf_https_web:", "bpf_laptop_not_arp:"])]),
    "3.1": ("who has?", "make capture AT=laptop:eth1 NAME=3.1 X=arp", [
        ("Follow along", ["printer_mac:", "request_dst_mac:      # the destination MAC of the laptop's ARP request"]),
        ("Challenge", ["asked_for_web:        # the IP address the laptop asked ARP about, to reach web",
                       "gateway_mac:"])]),
    "3.2": ("two answers", "make capture AT=laptop:eth1 NAME=3.2 X=dupip", [
        ("Follow along", ["duplicate_ip:", "impostor_mac:         # the MAC address that answered and isn't the printer's"]),
        ("Challenge", ["gratuitous_mac:       # who announced the address without being asked"])]),
    "4.1": ("DORA", "make capture AT=laptop:eth1 NAME=4.1 X=dhcp", [
        ("Follow along: from the Offer", ["offered_ip:", "server_id:            # option 54", "lease_seconds:"]),
        ("Challenge", ["router:", "dns_server:"])]),
    "4.2": ("the relay", "make capture AT=sw1:eth1,r1:eth2 NAME=4.2 X=dhcp", [
        ("Follow along: the Discover", ["lan_dst:              # its destination IP on sw1:eth1",
                                        "relay_dst:            # its destination IP on r1:eth2"]),
        ("Challenge", ["giaddr:               # the Relay agent IP address in r1's copy",
                       "offer_from:           # the Offer's source IP, on sw1:eth1"])]),
    "5.1": ("names and answers", "make capture AT=laptop:eth1 NAME=5.1 X=dns", [
        ("Follow along", ["web_ip:", "ttl:                  # of web.lab's answer, in seconds"]),
        ("Challenge", ["cname_target:         # the name intranet.lab is an alias for", "nxdomain_name:"])]),
    "5.2": ("the search domain", "make capture AT=laptop:eth1 NAME=5.2 X=search", [
        ("Follow along", ["first_name:           # the first name in a query",
                          "queries:              # every query the one ping caused"]),
        ("Challenge", ["bare_name_rcode:      # the response code for plain nas, like NXDOMAIN"])]),
    "6.1": ("a whole connection", "make capture AT=laptop:eth1 NAME=6.1 X=web", [
        ("Follow along", ["client_port:", "syn_ack_frame:        # its frame number, the No. column"]),
        ("Challenge", ["http_status:", "first_fin_from:       # the IP address that sent the first FIN"])]),
    "6.2": ("refused", "make capture AT=laptop:eth1 NAME=6.2 X=refused", [
        ("Follow along", ["refused_port:", "rst_from:"]),
        ("Challenge", ["refused_stream:       # tcp.stream of the refused connection"])]),
    "7.1": ("what TLS shows", "make capture AT=laptop:eth1 NAME=7.1 X=tls", [
        ("Follow along", ["sni:                  # both names, separated by a comma",
                          "tls_version:          # the version the server chose, like 1.2"]),
        ("Challenge", ["cipher:               # its name or its number",
                       "offered_alpn:         # what the laptop offered, separated by commas"])]),
    "7.2": ("decrypt your own", "make capture AT=laptop:eth1 NAME=7.2 X=tls12", [
        ("Follow along", ["tls_version:", "cert_cn:              # the name the certificate is for",
                          "cert_issuer:          # who signed it"]),
        ("Challenge", ["secret:               # the answer in secret.txt, once you've decrypted it"])]),
    "8.1": ("loss", "make break X=loss, then  make capture AT=laptop:eth1 NAME=8.1 X=big", [
        ("Follow along", ["retransmissions:", "retransmitted_by:     # the IP address that had to send again"]),
        ("Challenge", ["dup_acks:"])]),
    "8.2": ("the mystery fault",
            "make break X=mystery, then  make capture AT=laptop:eth1,r1:eth2,r2:eth2 NAME=8.2 X=webip", [
                ("Challenge", ["broken_router:        # r1 or r2", "cause:                # acl or route"])]),
    "8.3": ("the black hole", "make break X=mtu, then  make capture AT=laptop:eth1,sw1:eth1 NAME=8.3 X=tls", [
        ("Follow along", ["stuck_frame_bytes:    # the frame length of the one that never got an answer",
                          "big_frames_past_switch: # how many of those frames are in the sw1:eth1 copy"]),
        ("Challenge", ["dropped_by:           # the box that dropped them", "laptop_mtu:"])]),
}

if __name__ == "__main__":
    for t, (title, cap, parts) in A.items():
        lines = [f"# Task {t} · {title}",
                 "# Write each answer after its colon, save the file, then run:  make check T=" + t,
                 f"# The capture: {cap}",
                 f"# Guide: {G}/task-{t.replace('.', '-')}/", ""]
        for head, keys in parts:
            lines.append(f"# {head}")
            lines += keys
            lines.append("")
        pathlib.Path(f"answers/{t}.yml").write_text("\n".join(lines))
    print(f"wrote {len(A)} blank answers files")
