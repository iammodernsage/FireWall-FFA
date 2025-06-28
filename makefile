# Makefile for FireWall-FFA

CC := gcc
PKG_CONFIG := pkg-config

# Compiler flags

CFLAGS := -Wall -Wextra -O2 -std=c11 \
          -Icore-engine -Itraffic-inspector

# Linker flags (dynamically pulled from pkg-config)

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LDFLAGS := $(shell $(PKG_CONFIG) --libs openssl)

LDFLAGS := $(OPENSSL_LDFLAGS) -lpcre
CFLAGS += $(OPENSSL_CFLAGS)

# Target name

TARGET := FireWall-FFA

# Source files
SRC_CORE := core-engine/waf.c \
            core-engine/waf-rules.c

SRC_INSPECTOR := traffic-inspector/ja3-fingerprint.c \
                 traffic-inspector/tls-parser.c \
                 traffic-inspector/sni-extractor.c

SRC := $(SRC_CORE) $(SRC_INSPECTOR)
OBJ := $(SRC:.c=.o)

# Default build

all: $(TARGET)

# Link object files into final binary

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Compile C files to object files

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Debug build

debug: CFLAGS += -g -DDEBUG
debug: clean all

# Clean build artifacts

clean:
	rm -f $(OBJ) $(TARGET)

# Phony targets

.PHONY: all clean debug

run:
	python3 cli-tool/firewallctl.py start

stop:
	python3 cli-tool/firewallctl.py stop

status:
	python3 cli-tool/firewallctl.py status

reload:
	python3 cli-tool/firewallctl.py reload

install:
	bash scripts/install.sh
