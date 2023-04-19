# ebabypf

CO-RE ebpf program written in rust, base on  libbpf-rs

```
├── fentry.rs
├── hardirqs.rs
├── hello.rs
├── kprobe.rs
├── map.rs
├── perfevent.rs
├── ringbuffer.rs
├── runqlat.rs
├── tcpalive.rs
├── tcpconnlat.rs
├── tcpstates.rs
├── tcpv4connect.rs
├── tracepoint.rs
└── uprobe.rs
```
## build

CO-RE using `vmlinux.h` to provide BTF, which is different between some versions. To ensure correctness, the best way is to generate `vmlinux.h` by yourself

```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

build ebpf program

```shell
# build all
cargo build

# build one

cargo build --bin fentry
```


## use

```
sudo ./target/debug/tcpalive
```
