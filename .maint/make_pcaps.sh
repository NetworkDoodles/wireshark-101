#!/bin/sh
# Maintainers: record the reference captures in pcaps/ from a running lab, the same way a learner takes them.
# Run inside the dev container with the lab up:  sh .maint/make_pcaps.sh   (then make check from a fresh clone)
set -eu
cd "$(dirname "$0")/.."
make -s fix >/dev/null
make -s capture AT=sw1:eth1 NAME=mixed X=mixed >/dev/null
for t in 1.1 1.2 2.2 3.1 3.2 4.1 4.2 5.1 5.2 6.1 6.2 7.1 7.2 8.1 8.2 8.3; do
  rm -f captures/$t.json
  make -s solve T=$t >/dev/null
done
rm -f pcaps/*
for f in captures/*.pcapng captures/*.keys captures/*.json; do
  [ -e "$f" ] && cp "$f" pcaps/
done
ls -l pcaps
