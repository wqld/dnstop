build-image:
    cargo xtask build-ebpf
    RUSTFLAGS="-Clinker=aarch64-linux-musl-ld" cargo build --target aarch64-unknown-linux-musl
    podman build --build-arg ARCH=aarch64 -t dnstop:test .
