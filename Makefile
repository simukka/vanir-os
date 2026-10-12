# Build the user program, embed it in the kernel, wrap the kernel in a Limine ISO, run in QEMU.
#   make run                          normal boot
#   make run USER_FEATURES=hello/poke-kernel   isolation test: user reads kernel memory, must #PF
#   make run APP=tests/apps/two-spinners.toml   choose the app manifest (see apps/README.md)
#   make run-debug                    also log interrupts/CPU resets to qemu.log
#   make test                         boot every scenario in tests/run.sh and check the results
#   make test ACCEL=kvm               same, under KVM instead of QEMU's emulator
#   make run BOOT=uefi-secure ACCEL=kvm   boot through UEFI Secure Boot (see docs/index.html#boot-chain)

PROFILE        := release
TARGET_DIR     := target/x86_64-unknown-none/$(PROFILE)
LIMINE_BRANCH  := v11.x-binary
APP            := apps/default.toml
USER_PROGS     := hello spinner isolation runaway echo client deadlock supervisor crasher sleeper devprobe dmatest virtio-console chatter telemetry virtio-vsock attest control virtio-blk blktest storage unlocker virtio-net nictest net http mgmt-echo switcher agent
# Service images for generic slots (RFD 2), built into build/slots/: <name>:<program>:<descriptor>.
# The agent is built after them, since its test scripts carry them.
SLOT_IMAGES    := web-v1:http:tests/slots/web-v1.toml web-v2:http:tests/slots/web-v2.toml \
                  web-floor:http:tests/slots/web-floor.toml web-large:http:tests/slots/web-large.toml \
                  hello:hello:tests/slots/hello.toml crasher:crasher:tests/slots/crasher.toml
USER_FEATURES  :=
KERNEL_FEATURES:=
ISO            := build/vanir-os.iso
QEMU           = $(if $(TPM),tools/with-swtpm.sh )qemu-system-x86_64
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
# Slot images are signed with this key (the rogue-key test changes it).
SLOT_SIGNING_KEY := $(SIGNING_KEY)
# The control plane's keys, pinned in the agent (RFD 2, P7): its Noise static key and the key
# that signs desired state. tools/control-plane.py makes dev keys; CP_ADDR is where the agent
# dials (the host, through slirp, on the management network).
CP_KEY         := keys/cp-noise.key
CP_ADDR        := 10.0.2.2:7000
# Tests of the signature checks: changed after signing, shipped unsigned, signatures swapped (a:b).
TAMPER         :=
UNSIGNED       :=
SWAP_SIGS      :=
# Boot path: "bios" boots the Limine ISO (fast; nothing vouches for the bootloader) and
# "uefi-secure" boots OVMF with Secure Boot on and Debian's snakeoil test keys enrolled:
# firmware checks the signed Limine, Limine checks its enrolled config, the config pins the
# kernel's hash, and the kernel checks each task's signature.
BOOT           := bios
OVMF_CODE      := /usr/share/OVMF/OVMF_CODE_4M.snakeoil.fd
OVMF_VARS      := /usr/share/OVMF/OVMF_VARS_4M.snakeoil.fd
SB_CERT        := /usr/share/ovmf/PkKek-1-snakeoil.pem
SB_KEY_SOURCE  := /usr/share/ovmf/PkKek-1-snakeoil.key
SB_KEY_PASS    := snakeoil
SB_KEY         := build/secureboot.key
# Tests of the boot chain: kernel changed after hashing, config edited after enrolling, Limine
# left unsigned.
SB_TAMPER_KERNEL   :=
SB_EDIT_CONFIG     :=
SB_UNSIGNED_LOADER :=
# TPM=1 attaches a software TPM (swtpm, state in build/tpm): with BOOT=uefi-secure the firmware
# measures the boot loader and Secure Boot state, and the kernel measures itself and every task.
TPM            :=
# DISK=1 attaches build/disk.img (64 MiB, kept across runs) as a virtio block device;
# DISK_RESET=1 starts it from zeros.
DISK           :=
DISK_RESET     :=
# DISK_CORRUPT=volume:block flips a byte of that data block before booting (integrity tests).
DISK_CORRUPT   :=
DISK_FLAGS     = $(if $(DISK),-drive file=build/disk.img$(,)if=none$(,)id=d0$(,)format=raw \
                   -device virtio-blk-pci$(,)drive=d0$(,)disable-legacy=on)
# Networks. NET adds the data NIC and NET_MGMT the management NIC, each a virtio-net device at a
# fixed PCI address (data first, so it is the first one a manifest claims):
#   user   QEMU's NAT (slirp, with DHCP); host port NET_PORT (NET_MGMT_PORT) is forwarded to the
#          guest's port 80 (7)
#   dgram  raw Ethernet frames in UDP datagrams between QEMU (port NET_DGRAM_PORT, or
#          NET_MGMT_DGRAM_PORT) and tools/net-peer.py (the next port up); static addresses
NET            :=
NET_MGMT       :=
NET_PORT       ?= 8080
NET_MGMT_PORT  ?= 8081
NET_DGRAM_PORT ?= 18090
NET_MGMT_DGRAM_PORT ?= 18092
# $(call nic,backend,id,host port,guest port,dgram port,peer port,PCI address,MAC)
nic            = $(if $(1),$(if $(filter user,$(1)),-netdev user$(,)id=$(2)$(,)hostfwd=tcp:127.0.0.1:$(3)-:$(4),\
                   -netdev dgram$(,)id=$(2)$(,)local.type=inet$(,)local.host=127.0.0.1$(,)local.port=$(5)$(,)remote.type=inet$(,)remote.host=127.0.0.1$(,)remote.port=$(6)) \
                   -device virtio-net-pci$(,)netdev=$(2)$(,)disable-legacy=on$(,)addr=$(7)$(,)mac=$(8))
NET_FLAGS      = $(call nic,$(NET),data,$(NET_PORT),80,$(NET_DGRAM_PORT),$(shell echo $$(($(NET_DGRAM_PORT)+1))),0x10,52:54:00:00:00:01) \
                 $(call nic,$(NET_MGMT),mgmt,$(NET_MGMT_PORT),7,$(NET_MGMT_DGRAM_PORT),$(shell echo $$(($(NET_MGMT_DGRAM_PORT)+1))),0x11,52:54:00:00:00:02)
UEFI           := $(filter uefi-secure,$(BOOT))
IMAGE          := $(if $(UEFI),esp,$(ISO))
BOOT_FLAGS     := $(if $(UEFI),-M q35$(,)smm=on -global driver=cfi.pflash01$(,)property=secure$(,)value=on \
                    -drive if=pflash$(,)format=raw$(,)unit=0$(,)file=$(OVMF_CODE)$(,)readonly=on \
                    -drive if=pflash$(,)format=raw$(,)unit=1$(,)file=build/OVMF_VARS.fd \
                    -drive format=raw$(,)file=fat:rw:build/esp -nic none -m 256M,-M q35 -cdrom $(ISO) -nic none -m 128M)
CPU_FLAGS      := $(if $(filter kvm,$(ACCEL)),-enable-kvm -cpu host,-cpu max)
# The virtio console carries telemetry to the host (build/telemetry.log, or build/console.log when
# vsock does); COM1 stays the boot log.
CONSOLE_LOG    := $(if $(filter vsock,$(TRANSPORT)),build/console.log,build/telemetry.log)
VSOCK_FLAGS    := $(if $(filter vsock,$(TRANSPORT)),-device vhost-vsock-pci$(,)guest-cid=3)
QEMU_FLAGS     := $(BOOT_FLAGS) $(CPU_FLAGS) -serial stdio -display none \
                  -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
                  -device virtio-serial-pci,id=vser,disable-legacy=on \
                  -chardev file,id=tel,path=$(CONSOLE_LOG) -device virtconsole,chardev=tel,bus=vser.0 \
                  $(VSOCK_FLAGS) $(DISK_FLAGS) $(NET_FLAGS)

# The agent embeds the slot images, so it's built in a second cargo run, with its own features.
BUILD_PROGS           := $(filter-out agent,$(USER_PROGS))
USER_CARGO_FEATURES   := $(if $(filter-out agent/%,$(USER_FEATURES)),--features "$(filter-out agent/%,$(USER_FEATURES))")
AGENT_CARGO_FEATURES  := $(if $(filter agent/%,$(USER_FEATURES)),--features "$(filter agent/%,$(USER_FEATURES))")
KERNEL_CARGO_FEATURES := $(if $(KERNEL_FEATURES),--features $(KERNEL_FEATURES))

.PHONY: all iso esp image disk kernel user run run-debug test qemu-cmd clean distclean FORCE

all: $(ISO)

iso: $(ISO)

# Whatever BOOT boots from, and the disk if DISK is set.
image: $(IMAGE) $(if $(DISK),disk)

disk:
	@mkdir -p build
	$(if $(DISK_RESET),rm -f build/disk.img)
	[ -f build/disk.img ] || truncate -s 64M build/disk.img
	$(if $(DISK_CORRUPT),tools/corrupt-disk.py build/disk.img $(DISK_CORRUPT))

$(SIGNING_KEY):
	@mkdir -p $(dir $@)
	tools/sign-image.py gen-key $(SIGNING_KEY) $(SIGNING_PUB)

ifneq ($(SLOT_SIGNING_KEY),$(SIGNING_KEY))
$(SLOT_SIGNING_KEY):
	@mkdir -p $(dir $@)
	tools/sign-image.py gen-key $@ $(@:.key=.pub)
endif

$(CP_KEY):
	tools/control-plane.py gen-keys $(dir $@)

user: $(SIGNING_KEY) $(SLOT_SIGNING_KEY) $(CP_KEY) FORCE
	cargo build $(addprefix -p ,$(BUILD_PROGS)) --$(PROFILE) $(USER_CARGO_FEATURES)
	@mkdir -p build/slots
	for p in $(BUILD_PROGS); do objcopy --strip-all $(TARGET_DIR)/$$p build/$$p.elf; done
	for s in $(SLOT_IMAGES); do set -- $$(echo $$s | tr : ' '); \
	    cp build/$$2.elf build/slots/$$1.elf; \
	    tools/sign-image.py sign-slot $(SLOT_SIGNING_KEY) build/slots/$$1.elf $$3 build/slots/$$1 || exit 1; done
	VANIR_SLOTS="$(abspath build/slots)" VANIR_CP_PUB="$(abspath $(dir $(CP_KEY))cp-noise.pub)" \
	    VANIR_CP_SIGN_PUB="$(abspath $(dir $(CP_KEY))cp-sign.pub)" VANIR_CP_ADDR="$(CP_ADDR)" \
	    cargo build -p agent --$(PROFILE) $(AGENT_CARGO_FEATURES)
	objcopy --strip-all $(TARGET_DIR)/agent build/agent.elf
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

# Kernel, task images and signatures into $(1)/boot, then the signature-test switches.
define stage_boot_files
	mkdir -p $(1)/boot/limine
	cp $(TARGET_DIR)/vanir-kernel $(1)/boot/vanir-kernel
	for p in $(USER_PROGS); do cp build/$$p.elf build/$$p.sig $(1)/boot/; done
	for p in $(TAMPER); do printf X >> $(1)/boot/$$p.elf; done
	for pair in $(SWAP_SIGS); do a=$${pair%%:*}; b=$${pair##*:}; \
	    mv $(1)/boot/$$a.sig build/t.sig; mv $(1)/boot/$$b.sig $(1)/boot/$$a.sig; \
	    mv build/t.sig $(1)/boot/$$b.sig; done
endef

$(ISO): kernel limine/limine build/limine.conf
	rm -rf build/iso_root
	mkdir -p build/iso_root/EFI/BOOT
	$(call stage_boot_files,build/iso_root)
	cp build/limine.conf limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin \
	   build/iso_root/boot/limine/
	cp limine/BOOTX64.EFI build/iso_root/EFI/BOOT/
	xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
	   -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
	   -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin \
	   -efi-boot-part --efi-boot-image --protective-msdos-label \
	   build/iso_root -o $@ 2>/dev/null
	./limine/limine bios-install $@ 2>/dev/null

$(SB_KEY): $(SB_KEY_SOURCE)
	@mkdir -p build
	openssl pkey -in $< -passin pass:$(SB_KEY_PASS) -out $@
	chmod 600 $@

# EFI system partition for BOOT=uefi-secure (QEMU serves the directory as a FAT disk).
esp: kernel limine/limine build/limine.conf $(SB_KEY)
	rm -rf build/esp
	mkdir -p build/esp/EFI/BOOT
	$(call stage_boot_files,build/esp)
	# The config pins the kernel by BLAKE2b hash and sends Limine's messages to the serial port.
	{ printf 'serial: yes\n'; sed "s|^\(    path: boot():/boot/vanir-kernel\)$$|\1#$$(b2sum build/esp/boot/vanir-kernel | cut -d' ' -f1)|" \
	    build/limine.conf; } > build/esp/boot/limine/limine.conf
	# Limine refuses any config but this one; firmware refuses any Limine but this signed one.
	cp limine/BOOTX64.EFI build/esp/EFI/BOOT/BOOTX64.EFI
	./limine/limine enroll-config build/esp/EFI/BOOT/BOOTX64.EFI \
	    $$(b2sum build/esp/boot/limine/limine.conf | cut -d' ' -f1) >/dev/null
	$(if $(SB_UNSIGNED_LOADER),,sbsign --key $(SB_KEY) --cert $(SB_CERT) \
	    --output build/esp/EFI/BOOT/BOOTX64.EFI build/esp/EFI/BOOT/BOOTX64.EFI 2>/dev/null)
	$(if $(SB_TAMPER_KERNEL),printf X >> build/esp/boot/vanir-kernel)
	$(if $(SB_EDIT_CONFIG),sed -i 's/timeout: 0/timeout: 1/' build/esp/boot/limine/limine.conf)
	cp $(OVMF_VARS) build/OVMF_VARS.fd

# isa-debug-exit makes QEMU exit with (code << 1) | 1: 1 = clean exit(0), 3 = user exit(!=0),
# 5 = user fault, 7 = kernel fault/panic. Map 1 back to success for the shell.
run: image
	$(QEMU) $(QEMU_FLAGS); s=$$?; [ $$s -eq 1 ] || exit $$s

run-debug: image
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
