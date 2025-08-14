# OS Makefile with modular approach for 64-bit OS with GRUB Multiboot2

# Compilers and tools
ASM = nasm
CC = gcc
LD = ld

# Flags
ASMFLAGS = -f bin
CFLAGS = -ffreestanding -nostdlib -fpic -pie -e module_main -o

# Directories
BUILDDIR = build
OSDIR = $(BUILDDIR)/os

# Find all source files using wildcards
ASM_SOURCES = $(shell find . -name "*.asm" -not -path "./boot/*" -not -path "./kernel/*")
C_SOURCES = $(shell find . -name "*.c" -not -path "./kernel/*")
ELF_SOURCES = $(shell find . -name "*.elf" -not -path "./kernel/*" -not -path "./modules/apps/*" -not -path "./modules/sys/*")

# Generate corresponding binary module paths
ASM_MODULES = $(patsubst %.asm,$(BUILDDIR)/%.bin,$(ASM_SOURCES))
C_MODULES = $(patsubst %.c,$(BUILDDIR)/%.bin,$(C_SOURCES))
ELF_MODULES = $(patsubst %.elf,$(BUILDDIR)/%.elf,$(ELF_SOURCES))

.PHONY: all clean modules kernel

all: kernel modules

# Create build directories
$(BUILDDIR):
	mkdir -p $(BUILDDIR)
	mkdir -p $(OSDIR)/boot/grub
	mkdir -p $(OSDIR)/kernel

# Build kernel using the kernel Makefile
kernel: | $(BUILDDIR)
	$(MAKE) -C kernel

# Rule to create build directories for modules
define create_dir
	mkdir -p $(dir $@)
endef

# Compile ASM files directly to binary modules
$(BUILDDIR)/%.bin: %.asm
	$(create_dir)
	$(ASM) $(ASMFLAGS) $< -o $@

# Compile C files to binary modules
$(BUILDDIR)/%.bin: %.c
	$(create_dir)
	$(CC) $(CFLAGS) $@ $<

# Rule for ELF files (just copy them)
$(BUILDDIR)/%.elf: %.elf
	$(create_dir)
	cp $< $@

# Rule for BIN files (just copy them)
$(BUILDDIR)/%.bin: %.bin
	$(create_dir)
	cp $< $@

# Rule for SO files (just copy them)
$(BUILDDIR)/%.so: %.so
	$(create_dir)
	cp $< $@

# Copy all modules to the OS directory structure
modules: $(ASM_MODULES) $(C_MODULES) $(ELF_MODULES)
	# Copy all binary modules preserving directory structure
	for module in $(ASM_MODULES) $(C_MODULES) $(ELF_MODULES); do \
		target_dir=$$(dirname $${module#$(BUILDDIR)/}); \
		mkdir -p $(OSDIR)/$$target_dir; \
		cp $$module $(OSDIR)/$$target_dir/; \
	done

	# Copy any existing .elf files from modules/sys and modules/apps
	mkdir -p $(OSDIR)/modules/sys
	mkdir -p $(OSDIR)/modules/apps
	if [ -d "modules/sys" ]; then \
		find modules/sys -name "*.elf" -type f -exec cp {} $(OSDIR)/modules/sys/ \; ; \
	fi
	if [ -d "modules/apps" ]; then \
		find modules/apps -name "*.elf" -type f -exec cp {} $(OSDIR)/modules/apps/ \; ; \
	fi
	if [ -d "modules/sys" ]; then \
		find modules/sys -name "*.cfg" -type f -exec cp {} $(OSDIR)/modules/sys/ \; ; \
	fi
	if [ -d "modules/apps" ]; then \
		find modules/apps -name "*.cfg" -type f -exec cp {} $(OSDIR)/modules/apps/ \; ; \
	fi
	if [ -d "modules" ]; then \
		find modules -name "*.bin" -type f -exec cp {} $(OSDIR)/modules/ \; ; \
	fi
	if [ -d "modules" ]; then \
		find modules -name "*.so" -type f -exec cp {} $(OSDIR)/modules/ \; ; \
	fi
	
	# Create GRUB configuration file
	echo "set timeout=0" > $(OSDIR)/boot/grub/grub.cfg
	echo "set default=0" >> $(OSDIR)/boot/grub/grub.cfg
	echo "menuentry \"VOSTROX\" {" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    insmod fat" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    insmod vbe" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    insmod gfxterm" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    set root=hd0" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    multiboot2 /kernel/kernel.bin" >> $(OSDIR)/boot/grub/grub.cfg
	echo "    boot" >> $(OSDIR)/boot/grub/grub.cfg
	echo "}" >> $(OSDIR)/boot/grub/grub.cfg

clean:
	$(MAKE) -C kernel clean
	rm -rf $(BUILDDIR)
