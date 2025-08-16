# Kernel Makefile for VOSTROX OS

# Compilers and tools
ASM = nasm
CC = gcc
LD = ld

# Flags
KERNEL_ASMFLAGS = -f elf64
KERNEL_CFLAGS = -ffreestanding -mcmodel=kernel -mno-red-zone -mno-mmx \
         -fno-stack-protector -fno-pic -fno-pie -O2 -Wall -Wextra -c
KERNEL_LDFLAGS = -n -T linker.ld -nostdlib

# Directories
BUILDDIR = ../build
OSDIR = $(BUILDDIR)/os

# Kernel source files
KERNEL_C_SOURCES = $(wildcard *.c)
KERNEL_ASM_SOURCES = ../boot/header.asm
KERNEL_CONFIG_FILES = slist.cfg

# CHANGED: Combined file in kernel dir
KERNEL_COMBINED = kernel_combined.c
KERNEL_C_OBJECTS = $(BUILDDIR)/kernel/kernel.o
KERNEL_ASM_OBJECTS = $(patsubst ../boot/%.asm,$(BUILDDIR)/%.o,$(KERNEL_ASM_SOURCES))

# All objects
KERNEL_OBJECTS = $(KERNEL_C_OBJECTS) $(KERNEL_ASM_OBJECTS)

# Output binary
KERNEL_BIN = $(BUILDDIR)/kernel.bin

.PHONY: all clean

all: $(KERNEL_BIN) copy_configs

# Create build directories
$(BUILDDIR)/kernel:
	mkdir -p $(BUILDDIR)/kernel

# CHANGED: Create combined source file in kernel dir
# CHANGED: Create combined source file in kernel dir
$(KERNEL_COMBINED): $(KERNEL_C_SOURCES)
	echo '#include "include.h"' > $@
	for src in $(KERNEL_C_SOURCES); do \
		echo "/* === $$src === */" >> $@; \
		grep -v '^#include' $$src >> $@; \
	done

# CHANGED: Compile combined file
$(BUILDDIR)/kernel/kernel.o: $(KERNEL_COMBINED) | $(BUILDDIR)/kernel
	$(CC) $(KERNEL_CFLAGS) $< -o $@

# Compile ASM files
$(BUILDDIR)/%.o: ../boot/%.asm | $(BUILDDIR)/kernel
	$(ASM) $(KERNEL_ASMFLAGS) $< -o $@

# Link kernel
$(KERNEL_BIN): $(KERNEL_OBJECTS) linker.ld
	$(LD) $(KERNEL_LDFLAGS) -o $@ $(KERNEL_OBJECTS)
	mkdir -p $(OSDIR)/kernel
	cp $@ $(OSDIR)/kernel/kernel.bin

# Copy configuration files
copy_configs:
	mkdir -p $(OSDIR)/kernel
	for cfg in $(KERNEL_CONFIG_FILES); do \
		if [ -f $$cfg ]; then \
			cp $$cfg $(OSDIR)/kernel/; \
		fi \
	done

clean:
	rm -f $(KERNEL_OBJECTS) $(KERNEL_BIN) $(KERNEL_COMBINED)
