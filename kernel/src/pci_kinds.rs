// Devices an app manifest can grant, by name: (name, vendor, device ids). Shared by the kernel
// and kernel/build.rs (which rejects unknown names). Virtio 1.x devices use 0x1040 + the virtio
// device type; transitional ones also answer to the legacy id.
pub const KINDS: &[(&str, u16, &[u16])] = &[
    ("virtio-console", 0x1af4, &[0x1043, 0x1003]),
    ("virtio-vsock", 0x1af4, &[0x1053]),
    ("virtio-blk", 0x1af4, &[0x1042, 0x1001]),
];
