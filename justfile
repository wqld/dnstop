build-image:
    cargo xtask build-ebpf
    cargo build --target aarch64-unknown-linux-musl
    docker build --build-arg ARCH=aarch64 -t dnstop:test .
