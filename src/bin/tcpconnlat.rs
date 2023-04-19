// 以模块的形式将字节码引入到程序中
mod tcpconnlat {
    include!(concat!(env!("OUT_DIR"), "/tcpconnlat.skel.rs"));
}

use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use clap::Parser;
use ebabypf::*;
use libbpf_rs::{PerfBufferBuilder, PrintLevel};
use plain::Plain;
use tcpconnlat::*;

unsafe impl Plain for tcpconnlat_bss_types::event {}

#[derive(Debug, Clone, Copy, Parser)]
struct Command {
    #[clap(short, long)]
    verbose: bool,

    #[clap(short, long, default_value = "0")]
    pid: u32,

    #[clap(short, long, default_value = "0")]
    min_ns: u64,
}
fn init_libbpf_log() {
    let log_level = if let Ok(s) = env::var("LOG") {
        match s.as_str() {
            "DEBUG" => PrintLevel::Debug,
            _ => PrintLevel::Info,
        }
    } else {
        PrintLevel::Info
    };

    libbpf_rs::set_print(Some((
        log_level,
        |level: PrintLevel, msg: String| match level {
            PrintLevel::Debug => println!("{}", msg),
            _ => {}
        },
    )));
}

fn main() -> anyhow::Result<()> {
    init_libbpf_log();
    let opts = Command::parse();

    let mut skel_builder = TcpconnlatSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // 读取字节码
    let mut open_skel = skel_builder.open()?;

    if opts.min_ns != 0 {
        open_skel.rodata().target_min_us = opts.min_ns;
    }

    if opts.pid != 0 {
        open_skel.rodata().target_tgid = opts.pid;
    }

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    println!(
        "{:<10} {:20} {:<2} {:<32} {:<10} {:<32} {:<10} {:<10}",
        "PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)"
    );

    let perf = PerfBufferBuilder::new(&skel.maps_mut().events())
        .sample_cb(|_cpu, data: &[u8]| {
            let mut event = tcpconnlat_bss_types::event::default();
            plain::copy_from_bytes(&mut event, data).expect("parse failed");

            let comm = std::str::from_utf8(&event.comm)
                .expect("parse error")
                .trim_end_matches(char::from(0));

            let lport = b2l_u16(event.lport);
            let dport = b2l_u16(event.dport);

            match event.af {
                2 => unsafe {
                    let saddr: u32 = b2l_u32(event.__anon_1.saddr_v4);
                    let daddr: u32 = b2l_u32(event.__anon_2.daddr_v4);

                    println!(
                        "{:<10} {:20} {:<2} {:<32} {:<10} {:<32} {:<10} {:<10}",
                        event.tgid,
                        comm,
                        event.af,
                        Ipv4Addr::from(saddr),
                        lport,
                        Ipv4Addr::from(daddr),
                        dport,
                        event.delta,
                    )
                },
                10 => unsafe {
                    let saddr: u128 = b2l_u128_array(&event.__anon_1.saddr_v6);
                    let daddr: u128 = b2l_u128_array(&event.__anon_2.daddr_v6);

                    println!(
                        "{:<10} {:20} {:<2} {:<32} {:<10} {:<32} {:<10} {:<10}",
                        event.tgid,
                        comm,
                        event.af,
                        Ipv6Addr::from(saddr),
                        lport,
                        Ipv6Addr::from(daddr),
                        dport,
                        event.delta,
                    )
                },
                _ => {
                    return;
                }
            }
        })
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
