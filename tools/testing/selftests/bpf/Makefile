CFLAGS += -Wall -O2 -lcap -I../../../include/uapi -I../../../lib

test_objs = test_verifier test_tag test_maps test_lru_map test_lpm_map

TEST_PROGS := $(test_objs) test_kmod.sh
TEST_FILES := $(test_objs)
LIBBPF := ../../../lib/bpf/bpf.o

all: $(test_objs)

test_verifier: $(LIBBPF)
test_tag: $(LIBBPF)

include ../lib.mk

clean:
	$(RM) $(test_objs)
