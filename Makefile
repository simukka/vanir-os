# Build the user program, embed it in the kernel, wrap the kernel in a Limine ISO, run in QEMU.
#   make run                          normal boot
#   make run USER_FEATURES=hello/poke-kernel   isolation test: user reads kernel memory, must #PF
#   make run APP=tests/apps/two-spinners.toml   choose the app manifest (see apps/README.md)
#   make run-debug                    also log interrupts/CPU resets to qemu.log
#   make test                         boot every scenario in tests/run.sh and check the results
#   make test ACCEL=kvm               same, under KVM instead of QEMU's emulator

PROFILE        := release
TARGET_DIR     := target/x86_64-unknown-none/$(PROFILE)
LIMINE_BRANCH  := v11.x-binary
APP            := apps/default.toml
USER_PROGS     := hello spinner isolation runaway echo client deadlock supervisor crasher sleeper devprobe dmatest virtio-console chatter telemetry virtio-vsock
USER_FEATURES  :=
KERNEL_FEATURES:=
ISO            := build/vanir-os.iso
QEMU           := qemu-system-x86_64
, := ,
ACCEL          := tcg
# Telemetry uplink: "console" (virtio console -> build/telemetry.log) or "vsock" (vhost-vsock:
# needs /dev/vhost-vsock, i.e. the kvm group; tools/host-agent.py --listen-vsock receives it).
TRANSPORT      := console
# Task images are signed with this key (made on first build; keep it out of git) and version.
SIGNING_KEY    := keys/dev-signing.key
SIGNING_PUB    := $(SIGNING_KEY:.key=.pub)
# The public key compiled into the kernel: images must be signed with its private half.
TRUSTED_PUB    := $(SIGNING_PUB)
SIGN_VERSION   := 1
# Tests of the signature checks: changed after signing, shipped unsigned, signatures swapped (a:b).
TAMPER         :=
UNSIGNED       :=
SWAP_SIGS      :=
CPU_FLAGS      := $(if $(filter kvm,$(ACCEL)),-enable-kvm -cpu host,-cpu max)
# The virtio console carries telemetry to the host (build/telemetry.log, or build/console.log when
# vsock does); COM1 stays the boot log.
CONSOLE_LOG    := $(if $(filter vsock,$(TRANSPORT)),build/console.log,build/telemetry.log)
VSOCK_FLAGS    := $(if $(filter vsock,$(TRANSPORT)),-device vhost-vsock-pci$(,)guest-cid=3)
QEMU_FLAGS     := -M q35 $(CPU_FLAGS) -m 128M -cdrom $(ISO) -serial stdio -display none \
                  -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
                  -device virtio-serial-pci,id=vser,disable-legacy=on \
                  -chardev file,id=tel,path=$(CONSOLE_LOG) -device virtconsole,chardev=tel,bus=vser.0 \
                  $(VSOCK_FLAGS)

USER_CARGO_FEATURES   := $(if $(USER_FEATURES),--features "$(USER_FEATURES)")
KERNEL_CARGO_FEATURES := $(if $(KERNEL_FEATURES),--features $(KERNEL_FEATURES))

.PHONY: all iso kernel user run run-debug test qemu-cmd clean distclean FORCE

all: $(ISO)

iso: $(ISO)

$(SIGNING_KEY):
	@mkdir -p $(dir $@)
	tools/sign-image.py gen-key $(SIGNING_KEY) $(SIGNING_PUB)

user: $(SIGNING_KEY) FORCE
	cargo build $(addprefix -p ,$(USER_PROGS)) --$(PROFILE) $(USER_CARGO_FEATURES)
	@mkdir -p build
	for p in $(USER_PROGS); do objcopy --strip-all $(TARGET_DIR)/$$p build/$$p.elf; done
	tools/sign-image.py sign-all $(SIGNING_KEY) build $(USER_PROGS) --version $(SIGN_VERSION)

kernel: user
	VANIR_APP="$(abspath $(APP))" VANIR_SIGNING_PUB="$(abspath $(TRUSTED_PUB))" \
	    cargo build -p vanir-kernel --$(PROFILE) $(KERNEL_CARGO_FEATURES)

limine/limine:
	git clone --depth=1 --branch=$(LIMINE_BRANCH) https://github.com/limine-bootloader/limine.git limine
	$(MAKE) -C limine

# limine.conf plus one boot module per user program: the kernel finds task images by name.
build/limine.conf: limine.conf FORCE
	@mkdir -p build
	{ cat limine.conf; for p in $(USER_PROGS); do \
	    printf '    module_path: boot():/boot/%s.elf\n    module_string: %s\n' $$p $$p; \
	    case " $(UNSIGNED) " in *" $$p "*) ;; \
	    *) printf '    module_path: boot():/boot/%s.sig\n    module_string: %s.sig\n' $$p $$p;; esac; \
	done; } > $@

$(ISO): kernel limine/limine build/limine.conf
	rm -rf build/iso_root
	mkdir -p build/iso_root/boot/limine build/iso_root/EFI/BOOT
	cp $(TARGET_DIR)/vanir-kernel build/iso_root/boot/vanir-kernel
	for p in $(USER_PROGS); do cp build/$$p.elf build/$$p.sig build/iso_root/boot/; done
	for p in $(TAMPER); do printf X >> build/iso_root/boot/$$p.elf; done
	for pair in $(SWAP_SIGS); do a=$${pair%%:*}; b=$${pair##*:}; \
	    mv build/iso_root/boot/$$a.sig build/t.sig; mv build/iso_root/boot/$$b.sig build/iso_root/boot/$$a.sig; \
	    mv build/t.sig build/iso_root/boot/$$b.sig; done
	cp build/limine.conf limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin \
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

test:
	ACCEL=$(ACCEL) tests/run.sh

# Used by tests/run.sh so it boots with exactly the flags above.
qemu-cmd:
	@echo $(QEMU) $(QEMU_FLAGS)

clean:
	cargo clean
	rm -rf build qemu.log

distclean: clean
	rm -rf limine
