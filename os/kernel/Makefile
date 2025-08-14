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

# NEW: Shared object flags for kernel.so
KERNEL_SO_CFLAGS = -ffreestanding -fPIC -shared -nostdlib -nostartfiles \
                   -mno-red-zone -fno-stack-protector -O2 -m64 \
                   -fno-asynchronous-unwind-tables

# Directories
BUILDDIR = ../build
OSDIR = $(BUILDDIR)/os

# Kernel source files
KERNEL_C_SOURCES = kernel.c
KERNEL_ASM_SOURCES = ../boot/header.asm
KERNEL_CONFIG_FILES = slist.cfg

# Generate object file paths
KERNEL_C_OBJECTS = $(patsubst %.c,$(BUILDDIR)/kernel/%.o,$(KERNEL_C_SOURCES))
KERNEL_ASM_OBJECTS = $(patsubst ../boot/%.asm,$(BUILDDIR)/%.o,$(KERNEL_ASM_SOURCES))

# All objects
KERNEL_OBJECTS = $(KERNEL_C_OBJECTS) $(KERNEL_ASM_OBJECTS)

# Output binary
KERNEL_BIN = $(BUILDDIR)/kernel.bin
KERNEL_SO = $(BUILDDIR)/kernel.so

.PHONY: all clean

all: $(KERNEL_BIN) copy_configs

# Create build directories
$(BUILDDIR)/kernel:
	mkdir -p $(BUILDDIR)/kernel

# Compile C files
$(BUILDDIR)/kernel/%.o: %.c | $(BUILDDIR)/kernel
	$(CC) $(KERNEL_CFLAGS) $< -o $@

# Compile ASM files
$(BUILDDIR)/%.o: ../boot/%.asm | $(BUILDDIR)/kernel
	$(ASM) $(KERNEL_ASMFLAGS) $< -o $@

# Link kernel
$(KERNEL_BIN): $(KERNEL_OBJECTS) linker.ld
	$(LD) $(KERNEL_LDFLAGS) -o $@ $(KERNEL_OBJECTS)
	mkdir -p $(OSDIR)/kernel
	cp $@ $(OSDIR)/kernel/kernel.bin

# NEW: Build kernel.so (shared object version)
$(KERNEL_SO): kernel.c
	$(CC) $(KERNEL_SO_CFLAGS) kernel.c -o $@
	cp $@ $(OSDIR)/modules/sys/kernel.so

# Copy configuration files
copy_configs:
	mkdir -p $(OSDIR)/kernel
	for cfg in $(KERNEL_CONFIG_FILES); do \
		if [ -f $$cfg ]; then \
			cp $$cfg $(OSDIR)/kernel/; \
		fi \
	done

clean:
	rm -f $(KERNEL_OBJECTS) $(KERNEL_BIN)