# Makefile for FireWall-FFA

# Compiler and tools
CC = gcc
PKG_CONFIG = pkg-config

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -g -std=c11
CFLAGS += $(shell $(PKG_CONFIG) --cflags openssl)
CFLAGS += -Icore-engine -Itraffic-inspector

# Linker flags
LDFLAGS = $(shell $(PKG_CONFIG) --libs openssl)
LDFLAGS += -lpthread

# Source and object files
SRC_DIRS = core-engine traffic-inspector
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS = $(SRCS:.c=.o)

# Output binary
TARGET = waf

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compilation rule
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(TARGET) $(OBJS)

all: $(TARGET)

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
