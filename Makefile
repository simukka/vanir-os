# Build the user program, embed it in the kernel, wrap the kernel in a Limine ISO, run in QEMU.
#   make run                          normal boot
#   make run USER_FEATURES=poke-kernel   isolation test: user reads kernel memory, must #PF
#   make run-debug                    also log interrupts/CPU resets to qemu.log
#   make test                         boot headless and check the exit status / output

PROFILE        := release
TARGET_DIR     := target/x86_64-unknown-none/$(PROFILE)
LIMINE_BRANCH  := v11.x-binary
USER_FEATURES  :=
ISO            := build/vanir-os.iso
QEMU           := qemu-system-x86_64
QEMU_FLAGS     := -M q35 -m 128M -cdrom $(ISO) -serial stdio -display none \
                  -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04

CARGO_FEATURES := $(if $(USER_FEATURES),--features $(USER_FEATURES))

.PHONY: all kernel user run run-debug test clean distclean FORCE

all: $(ISO)

user: FORCE
	cargo build -p hello --$(PROFILE) $(CARGO_FEATURES)
	@mkdir -p build
	objcopy -O binary $(TARGET_DIR)/hello build/hello.bin

kernel: user
	cargo build -p vanir-kernel --$(PROFILE)

limine/limine:
	git clone --depth=1 --branch=$(LIMINE_BRANCH) https://github.com/limine-bootloader/limine.git limine
	$(MAKE) -C limine

$(ISO): kernel limine/limine limine.conf
	rm -rf build/iso_root
	mkdir -p build/iso_root/boot/limine build/iso_root/EFI/BOOT
	cp $(TARGET_DIR)/vanir-kernel build/iso_root/boot/vanir-kernel
	cp limine.conf limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin \
	   build/iso_root/boot/limine/
	cp limine/BOOTX64.EFI build/iso_root/EFI/BOOT/
	xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
	   -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
	   -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin \
	   -efi-boot-part --efi-boot-image --protective-msdos-label \
	   build/iso_root -o $@ 2>/dev/null
	./limine/limine bios-install $@ 2>/dev/null

# isa-debug-exit makes QEMU exit with (code << 1) | 1: 1 = clean exit(0), 3 = user exit(!=0),
# 5 = user fault, 7 = kernel fault/panic. Map 1 back to success for the shell.
run: $(ISO)
	$(QEMU) $(QEMU_FLAGS); s=$$?; [ $$s -eq 1 ] || exit $$s

run-debug: $(ISO)
	$(QEMU) $(QEMU_FLAGS) -d int,cpu_reset -D qemu.log; s=$$?; [ $$s -eq 1 ] || exit $$s

test: $(ISO)
	@out=$$(timeout 20 $(QEMU) $(QEMU_FLAGS)); s=$$?; echo "$$out"; \
	 echo "$$out" | grep -q 'hello from ring 3' && \
	 echo "$$out" | grep -q 'exited with code 0 (called from CPL 3)' && [ $$s -eq 1 ] \
	 && echo "PASS" || { echo "FAIL (qemu status $$s)"; exit 1; }

clean:
	cargo clean
	rm -rf build qemu.log

distclean: clean
	rm -rf limine
