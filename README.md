# dnstop
An efficient DNS monitoring tool based on eBPF

## Introduction

`dnstop` is attached to a specific network interface and simply outputs the results of DNS queries and responses that are forwarded to it in the form shown below.

```sh
REQ: ID=40797 SRC=192.168.64.6:54110 DST=192.168.64.1:53 DNS_NAME=www.google.com DNS_TYPE=A DNS_CLASS=IN
REQ: ID=39114 SRC=192.168.64.6:40193 DST=192.168.64.1:53 DNS_NAME=www.google.com DNS_TYPE=AAAA DNS_CLASS=IN
OK: ID=40797 DNS_NAME=www.google.com DNS_TYPE=A DNS_CLASS=IN
OK: ID=39114 DNS_NAME=www.google.com DNS_TYPE=AAAA DNS_CLASS=IN
REQ: ID=25132 SRC=192.168.64.6:44543 DST=192.168.64.1:53 DNS_NAME=www.woogole.com DNS_TYPE=A DNS_CLASS=IN
REQ: ID=55755 SRC=192.168.64.6:39533 DST=192.168.64.1:53 DNS_NAME=www.woogole.com DNS_TYPE=AAAA DNS_CLASS=IN
NXDOMAIN: ID=25132 DNS_NAME=www.woogole.com DNS_TYPE=A DNS_CLASS=IN
NXDOMAIN: ID=55755 DNS_NAME=www.woogole.com DNS_TYPE=AAAA DNS_CLASS=IN
REQ: ID=42662 SRC=192.168.64.6:34430 DST=192.168.64.1:53 DNS_NAME=www.woogole.com DNS_TYPE=A DNS_CLASS=IN
REQ: ID=42543 SRC=192.168.64.6:48084 DST=192.168.64.1:53 DNS_NAME=www.woogole.com DNS_TYPE=AAAA DNS_CLASS=IN
NXDOMAIN: ID=42662 DNS_NAME=www.woogole.com DNS_TYPE=A DNS_CLASS=IN
NXDOMAIN: ID=42543 DNS_NAME=www.woogole.com DNS_TYPE=AAAA DNS_CLASS=IN
```

## Prerequisites

- Rust
- Docker
- Justfile

## How to use

### 1. clone the repository

```bash
git clone https://github.com/wqld/dnstop.git
```

### 2. build the project

```bash
just build-image
```

You can specify the target architecture as follows. (default: aarch64).

```bash
just build-image --arch x86_64
```

### 3. run the container

It requires privileged privileges because it needs to run the eBPF program.
Specify the network interface to watch for DNS packets with the `--iface` option. (default: `eth0`)

```bash
docker run --privileged --rm --network host dnstop:manually --iface enp0s1
```

## Goal

This project was started to make it easy to verify that all DNS queries from an application running inside a specific Pod on Kubernetes are handled correctly. Therefore, the following command can be used to accomplish this goal:

```bash
kubectl debug {POD_NAME} --image=dnstop:manually --profile='sysadmin' --it
```
