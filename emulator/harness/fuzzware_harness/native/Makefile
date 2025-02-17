OWN_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UC_DIRNAME := fuzzware-unicorn

LIBDIR = $(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/
INC=-I$(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/include
BIN_EXT = .so

CC = clang
# ifeq ($(DEBUG_TIMER),1)
# 	CFLAGS += -fpic -Wall -Werror $(INC) -g -O3 -DDEBUG_TIMER
# else
# 	CFLAGS += -fpic -Wall -Werror $(INC) -g -O3
# endif
ifeq ($(DEBUG_TIMER),1)
	CFLAGS += -fpic -Wall $(INC) -g -O3 -DDEBUG_TIMER
else
	CFLAGS += -fpic -Wall $(INC) -g -O3
endif

ifeq ($(TEGRA),1)
	CFLAGS += -DTEGRA
endif

ifeq ($(ARMV4T),1)
	CFLAGS += -DARMV4T
endif

LDFLAGS += -shared -L$(LIBDIR) -lunicorn

.PHONY: all clean

SOURCES = native_hooks.c timer.c interrupt_triggers.c util.c state_snapshotting.c native_tracing.c uc_snapshot.c
SOURCES += core_peripherals/cortexm_nvic.c core_peripherals/cortexm_systick.c

BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

native_hooks.so: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

all: native_hooks.so

clean:
	rm -rf *.o core_peripherals/*.o $(BINS)
