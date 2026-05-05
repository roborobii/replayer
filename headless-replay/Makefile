SHELL := /bin/bash

# Pass-through variables. Override on the command line, e.g.
#   make up RECORDING_ID=archer-gameplay-v1 SPEED=1.0
RECORDING_ID ?=
SPEED ?= 1.0
REWRITE_HOST ?= 10.42.0.10
SWAP_WITH_CHARACTER ?=
LOGIN_SLOT ?= 0
SKIP_LOGIN ?=
INJECT_DELAY ?= 12
TOKEN ?=
WINEDEBUG ?= -all

export RECORDING_ID
export SPEED
export REWRITE_HOST
export SWAP_WITH_CHARACTER
export LOGIN_SLOT
export SKIP_LOGIN
export INJECT_DELAY
export TOKEN
export WINEDEBUG

.PHONY: up up-bg down logs status help client-shell client-logs wineprefix-reset trace trace-shell

# --- tracer service (pure-Python Unicorn x86 emulation, no wine) ---
FN_VA ?= 0x000EF6D8
SELF_PTR ?=
FLAGS ?=
XY_PACKED ?=
BTN ?= 1
TRACE_NAME ?= trace

export FN_VA
export SELF_PTR
export FLAGS
export XY_PACKED
export BTN
export TRACE_NAME

help:
	@echo "headless-replay targets:"
	@echo "  up                - docker compose up --build (foreground)"
	@echo "  up-bg             - docker compose up --build -d (background)"
	@echo "  down              - docker compose down"
	@echo "  logs              - follow replay-server logs"
	@echo "  status            - docker compose ps"
	@echo "  client-shell      - bash into a fresh wine-client container"
	@echo "  client-logs       - follow wine-client logs"
	@echo "  wineprefix-reset  - drop the wineprefix volume (forces fresh wineboot)"
	@echo "  trace             - run the Unicorn tracer (--profile tracer)"
	@echo "  trace-shell       - bash into the tracer container"
	@echo ""
	@echo "Variables (override on command line):"
	@echo "  RECORDING_ID         (default: latest by mtime)"
	@echo "  SPEED                (default: $(SPEED))"
	@echo "  REWRITE_HOST         (default: $(REWRITE_HOST))"
	@echo "  SWAP_WITH_CHARACTER  (default: <unset>)"
	@echo "  LOGIN_SLOT           (default: $(LOGIN_SLOT))"
	@echo "  SKIP_LOGIN           (default: <unset>)"
	@echo "  INJECT_DELAY         (default: $(INJECT_DELAY))"
	@echo "  TOKEN                (default: <wine-replay default>)"
	@echo "  WINEDEBUG            (default: $(WINEDEBUG))"

up:
	docker compose up --build

up-bg:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f replay-server

status:
	docker compose ps

client-shell:
	docker compose run --rm --entrypoint bash wine-client

client-logs:
	docker compose logs -f wine-client

wineprefix-reset:
	docker compose down && docker volume rm headless-replay_wineprefix || true

trace:
	docker compose --profile tracer run --rm tracer

trace-shell:
	docker compose --profile tracer run --rm --entrypoint bash tracer
