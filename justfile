arch := "aarch64"

build-image:
    cargo xtask build-ebpf
    cargo build --target {{ arch }}-unknown-linux-musl
    docker build --build-arg ARCH={{ arch }} -t dnstop:manually .
