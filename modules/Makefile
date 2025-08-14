#CC = gcc
#LD = ld
#OBJCOPY = objcopy
#
## ELF shared object flags
#CFLAGS = -ffreestanding -fPIC -shared -nostdlib -nostartfiles \
#         -mno-red-zone -fno-stack-protector -O2 -m64 \
#         -fno-asynchronous-unwind-tables -mcmodel=small
#
## Directories
#BUILDDIR = build
#OSDIR = ../os/build/os
#
## Find all .c files except port.c
#C_SOURCES = $(notdir $(filter-out port.c, $(wildcard *.c)))
#
## Generate corresponding .so files
#OBJ_FILES = $(patsubst %.c,$(BUILDDIR)/%.o,$(C_SOURCES))
#SO_FILES = $(patsubst %.o,$(BUILDDIR)/%.so,$(OBJ_FILES))
#
## Build port.o
#PORT_OBJ = $(BUILDDIR)/port.o
#
#.PHONY: all clean install
#
## Build all .so files
#all: $(SO_FILES) install
#
## Create build directory
#$(BUILDDIR):
#	mkdir -p $(BUILDDIR)
#
## Compile each source file to .o
#$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
#	$(CC) -c $(CFLAGS) $< -o $@
#
## Link each .o to .so without port.o
#$(BUILDDIR)/%.so: $(BUILDDIR)/%.o
#	$(CC) $(CFLAGS) $< -o $@
#
## Install all .so files to OS modules/sys directory
#install: $(SO_FILES)
#	mkdir -p $(OSDIR)/modules/sys
#	cp $(BUILDDIR)/*.so $(OSDIR)/modules/sys/
#	@echo "Installed all modules to $(OSDIR)/modules/sys/"
#
## Clean build directory entirely
#clean:
#	rm -rf $(BUILDDIR)
#	@echo "Cleaned build directory"
#
## Show what will be built
#list:
#	@echo "Found C sources: $(C_SOURCES)"
#	@echo "Will build: $(SO_FILES)"
#	@echo "Port object: $(PORT_OBJ)"
