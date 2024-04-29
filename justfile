arch := "aarch64"

build-image:
    cargo xtask build-ebpf --release
    cargo build --target {{ arch }}-unknown-linux-musl --release
    docker build --build-arg ARCH={{ arch }} -t dnstop:manually .
