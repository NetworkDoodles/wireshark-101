# Network Doodles lab · Wireshark 101
# Guide: https://networkdoodles.com/labs/wireshark-101/
#
# Tasks are numbered chapter.task, so T=2.1 is chapter 2, task 1. CH=<n> means a whole chapter.
.DEFAULT_GOAL := help
# The dev container keeps its venv outside the repo (VENV is set there); locally it is .venv.
VENV ?= .venv
PY := $(VENV)/bin/python
TOPO := lab/topology.clab.yml
BOLT := ghcr.io/dkhenderson2/capeos-bolt:0.11.0
HOST := nd-wshost:1
SHARK := nd-shark:1
WIRESHARK := lscr.io/linuxserver/wireshark:4.6.9
NODES := laptop printer broken-pc web dns sw1 r1 r2
T ?=
CH ?=
H ?=
AT ?=
NAME ?=
X ?=
FOR ?=
F ?=

help: ## show this help
	@grep -hE '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

REQS := requirements.txt
REQ_HASH = $(shell python3 -c "import hashlib,sys; print(hashlib.sha256(b''.join(open(f,'rb').read() for f in sys.argv[1:])).hexdigest()[:16])" $(REQS))

setup: ## create the Python venv the checker uses
	@if [ "$$(cat $(VENV)/.ok 2>/dev/null)" = "$(REQ_HASH)" ] && [ -x $(PY) ]; then exit 0; fi; \
	echo "installing the checker's Python packages into $(VENV)"; \
	if command -v uv >/dev/null; then \
	  uv venv -q --allow-existing --python 3.13 $(VENV) && uv pip install -q --python $(PY) -r $(REQS); \
	else \
	  python3 -m venv $(VENV) && $(PY) -m pip install -q -r $(REQS); \
	fi && echo "$(REQ_HASH)" > $(VENV)/.ok

# The dev container's own Docker engine starts alongside the container, so the first commands can beat it.
docker-ready:
	@for i in $$(seq 1 60); do docker info >/dev/null 2>&1 && exit 0; [ $$i = 1 ] && echo "  waiting for Docker to start ..."; sleep 2; done; \
	echo "Docker isn't answering. In the dev container it starts on its own; on a laptop, start Docker Desktop."; exit 1

images: docker-ready ## pull the switch image and build the hosts' and tshark's images (the dev container does this once)
	@docker image inspect $(BOLT) >/dev/null 2>&1 || docker pull -q $(BOLT)
	@docker build -q -t $(HOST) lab/host >/dev/null && echo "  built $(HOST), the lab's hosts"
	@docker build -q -t $(SHARK) lab/shark >/dev/null && echo "  built $(SHARK): tshark $$(docker run --rm $(SHARK) -v | head -1 | awk '{print $$3}')"

up: setup docker-ready ## start the network: a switch, two routers and five hosts (about a minute)
	@command -v containerlab >/dev/null || (echo "containerlab isn't installed: it comes with the dev container"; exit 2)
	@$(MAKE) -s images
	@rm -rf lab/.state
	containerlab deploy -t $(TOPO) --reconfigure
	@$(PY) lab/wait.py

down: ## remove the network (your captures and answers stay)
	containerlab destroy -t $(TOPO) --cleanup

reset: ## everything back to how it started, faults included (captures and answers stay)
	$(MAKE) up

shell: ## log in to a host, the switch or a router:  make shell H=laptop
	@case " $(NODES) " in *" $(H) "*) ;; *) echo "usage: make shell H=<name>   one of: $(NODES)"; exit 2;; esac
	@case "$(H)" in sw1|r1|r2) docker exec -it $(H) capeos-cli;; *) docker exec -it -w /root $(H) bash;; esac

status: ## what's running, and where to start  (WAIT=1 waits for the network)
	@$(PY) lab/status.py $(if $(WAIT),--wait)

ports: ## every port you can capture on, and what's at the other end of its cable
	@sudo -n containerlab capture -t $(TOPO) --list 2>/dev/null || containerlab capture -t $(TOPO) --list

capture: ## record traffic:  make capture AT=laptop:eth1 NAME=1.1 X=ping   (FOR=30s, F="capture filter")
	@test -n "$(AT)" -a -n "$(NAME)" || (echo 'usage: make capture AT=<node:port>[,<node:port>] NAME=<name> [X=<traffic>] [FOR=20s] [F="<capture filter>"]'; exit 2)
	@$(PY) lab/capture.py --at '$(AT)' --name '$(NAME)' $(if $(X),--x '$(X)') $(if $(FOR),--for '$(FOR)') $(if $(F),--filter '$(F)')

traffic: ## send the lab's scripted traffic:  make traffic X=ping   (make traffic lists them)
	@$(PY) lab/traffic.py $(if $(X),$(X),--list)

wireshark: docker-ready ## open Wireshark in your browser, with captures/ and pcaps/ in its File > Open
	@docker rm -f wireshark >/dev/null 2>&1 || true
	@docker image inspect $(WIRESHARK) >/dev/null 2>&1 || (echo "  pulling Wireshark (about 700 MB, once) ..."; docker pull -q $(WIRESHARK) >/dev/null)
	@mkdir -p captures
	@docker run -d --name wireshark -p 127.0.0.1:3000:3000 --shm-size 1g -e PUID=$$(id -u) -e PGID=$$(id -g) -e TZ=Etc/UTC \
	  -e SUBFOLDER=/wireshark/ -v "$(CURDIR)/captures:/captures" -v "$(CURDIR)/pcaps:/pcaps:ro" $(WIRESHARK) >/dev/null
	@echo "\n  Wireshark is starting. Open the Wireshark tab in the lab app (port 8000: 'Lab' in the PORTS tab,"
	@echo "  or http://localhost:8000 on a laptop). Your captures are in /captures, the reference ones in /pcaps."
	@echo "  make wireshark-stop closes it.\n"

wireshark-stop: ## close the browser Wireshark
	@docker rm -f wireshark >/dev/null 2>&1 && echo "  Wireshark stopped" || echo "  Wireshark wasn't running"

check: ## verify a task, a chapter or everything:  make check T=1.1 · CH=1 · (nothing)
	@$(PY) checks/check.py $(if $(T),$(T),$(if $(CH),ch$(CH),all))

solve: ## stuck? capture the task's traffic for you and fill in its answers, printing every step:  make solve T=1.2
	@test -n "$(T)" || (echo "usage: make solve T=<chapter.task>, e.g. T=1.2"; exit 2)
	@$(PY) lab/solve.py solve $(T)

skip: ## skip a task without the lab running: use the reference capture and fill in the answers:  make skip T=1.2
	@test -n "$(T)" || (echo "usage: make skip T=<chapter.task>, e.g. T=1.2"; exit 2)
	@$(PY) lab/solve.py skip $(T)

break: ## chapter 8's faults, on purpose:  make break X=loss · X=mystery · X=mtu
	@test -n "$(X)" || (echo "usage: make break X=loss|mystery|mtu"; exit 2)
	@$(PY) lab/solve.py break $(X)

fix: ## undo every fault make break set up
	@$(PY) lab/solve.py fix

.PHONY: help setup docker-ready images up down reset shell status ports capture traffic wireshark wireshark-stop check solve skip break fix
