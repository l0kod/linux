# SPDX-License-Identifier: GPL-2.0

all:

include ../lib.mk

.PHONY: all clean

BINARIES := test_omayexec
CFLAGS += -Wl,-no-as-needed -Wall -Werror
LDFLAGS += -lcap

test_omayexec: test_omayexec.c ../kselftest_harness.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

TEST_PROGS += $(BINARIES)
EXTRA_CLEAN := $(BINARIES)

all: $(BINARIES)
