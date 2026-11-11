# tshark and tcpdump for the lab: Wireshark's command-line twin, the same dissectors as the desktop app.
# Alpine 3.23 ships tshark 4.6 (the dev container's Debian has only 4.0).
FROM alpine:3.23
RUN apk add --no-cache tshark tcpdump
ENV HOME=/tmp
ENTRYPOINT ["tshark"]
