# The lab's hosts: a small Linux computer with the everyday network tools.
#   ip (iproute2)   addresses, routes and the neighbor (ARP) table
#   ping, traceroute, arp (net-tools), dig and nslookup (bind-tools), curl
#   udhcpc          the DHCP client (part of busybox)
#   dnsmasq         DNS and DHCP, on the dns host only
#   nginx, openssl  HTTP and HTTPS, on the web host only
FROM alpine:3.22
RUN apk add --no-cache bash iproute2 iputils traceroute net-tools bind-tools curl dnsmasq busybox-extras \
        nginx openssl ethtool \
 && echo 'PS1="\h:\w# "' > /root/.bashrc
# The lab's own certificate authority and the web server's certificate, made fresh when the image is built
# (never committed). Every host trusts the CA, so curl https://web.lab works without -k.
RUN mkdir -p /etc/lab-tls && cd /etc/lab-tls \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/O=Network Doodles Lab/CN=Network Doodles Lab CA" \
        -keyout ca.key -out ca.crt 2>/dev/null \
 && openssl req -newkey rsa:2048 -nodes -subj "/O=Network Doodles Lab/CN=web.lab" -keyout web.key -out web.csr 2>/dev/null \
 && printf 'subjectAltName=DNS:web.lab,DNS:intranet.lab\nextendedKeyUsage=serverAuth\n' > web.ext \
 && openssl x509 -req -in web.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -extfile web.ext -out web.crt 2>/dev/null \
 && rm ca.key web.csr \
 && cat ca.crt >> /etc/ssl/certs/ca-certificates.crt
COPY nginx.conf /etc/nginx/nginx.conf
COPY udhcpc.script /usr/share/udhcpc/default.script
COPY start.sh /usr/local/bin/start
CMD ["sleep", "infinity"]
