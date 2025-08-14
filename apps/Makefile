# apps/Makefile
CC = gcc
LD = ld

CFLAGS = -mno-red-zone -fno-stack-protector -fno-pic -fno-pie \
         -O0 -fcf-protection=none \
		 -c -m64 -march=x86-64 -mtune=generic
LDFLAGS = -n -T linker.ld -e _start

# List of applications to build
APPS =  vwm.elf test.elf

# Build test app
test.elf: test.o
	$(LD) $(LDFLAGS) -o test.elf test.o
	objcopy --remove-section .note.gnu.property test.elf test.elf
	@echo "Removing old test.elf file..."
	rm -f ../os/build/os/modules/apps/test.elf
	@echo "Copying new test.elf file..."
	cp test.elf ../os/build/os/modules/apps/
	@echo "test.elf deployed successfully!"

vwm.elf: vwm.o
	$(LD) $(LDFLAGS) -o vwm.elf vwm.o
	objcopy --remove-section .note.gnu.property vwm.elf vwm.elf
	rm -f ../os/build/os/modules/apps/vwm.elf
	cp vwm.elf ../os/build/os/modules/apps/

# Build all apps
all: $(APPS)

# Generic rule for object files
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

# Clean up
clean:
	rm -f *.o *.elf

# Individual targets for convenience
test: test.elf
vwm: vwm.elf