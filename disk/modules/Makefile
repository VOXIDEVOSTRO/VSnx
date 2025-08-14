CC = gcc
LD = ld
OBJCOPY = objcopy

# ELF shared object flags
CFLAGS = -ffreestanding -fPIC -shared -nostdlib -nostartfiles \
         -mno-red-zone -fno-stack-protector -O2 -m64 \
         -fno-asynchronous-unwind-tables -mcmodel=small

# Directories
BUILDDIR = build
OSDIR = ../os/build/os

# Find all .c files except port.c
C_SOURCES = $(filter-out port.c, $(wildcard *.c))

# Generate corresponding .so files
SO_FILES = $(patsubst %.c,$(BUILDDIR)/%.so,$(C_SOURCES))

# Build port.o
PORT_OBJ = $(BUILDDIR)/port.o

.PHONY: all clean install

# Build all .so files
all: $(SO_FILES) install

# Create build directory
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Build port.o (not shared)
$(PORT_OBJ): port.c port.h | $(BUILDDIR)
	$(CC) -ffreestanding -fPIC -nostdlib -mno-red-zone -fno-stack-protector -O2 -m64 -c port.c -o $(PORT_OBJ)

# Rule to build .so files, linking with port.o
$(BUILDDIR)/%.so: %.c $(PORT_OBJ) | $(BUILDDIR)
	$(CC) $(CFLAGS) $< $(PORT_OBJ) -o $@

# Install all .so files to OS modules/sys directory
install: $(SO_FILES)
	mkdir -p $(OSDIR)/modules/sys
	cp $(BUILDDIR)/*.so $(OSDIR)/modules/sys/
	@echo "Installed all modules to $(OSDIR)/modules/sys/"

# Clean build directory entirely
clean:
	rm -rf $(BUILDDIR)
	@echo "Cleaned build directory"

# Show what will be built
list:
	@echo "Found C sources: $(C_SOURCES)"
	@echo "Will build: $(SO_FILES)"
	@echo "Port object: $(PORT_OBJ)"
