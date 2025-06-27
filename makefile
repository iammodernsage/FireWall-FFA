# Makefile for FireWall-FFA

CC = gcc
CFLAGS = -Wall -Icore-engine -Itraffic-inspector
BIN = core-engine/waf

SRC_CORE = core-engine/waf.c core-engine/waf_rules.c
SRC_TLS  = traffic-inspector/ja3-fingerprint.c traffic-inspector/sni-extractor.c traffic-inspector/TLS-parser.c
SRC_ALL  = $(SRC_CORE) $(SRC_TLS)

.PHONY: all build clean run install

all: build

build:
	$(CC) $(CFLAGS) $(SRC_ALL) -o $(BIN)

run:
	python3 cli-tool/firewallctl.py start

stop:
	python3 cli-tool/firewallctl.py stop

status:
	python3 cli-tool/firewallctl.py status

reload:
	python3 cli-tool/firewallctl.py reload

clean:
	rm -f core-engine/waf

install:
	bash scripts/install.sh
