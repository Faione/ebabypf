// 以模块的形式将字节码引入到程序中
mod tcpstates {
    include!(concat!(env!("OUT_DIR"), "/tcpstates.skel.rs"));
}

use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use clap::Parser;
use ebabypf::{b2l_u128_array, b2l_u16, b2l_u32};
use libbpf_rs::{PerfBufferBuilder, PrintLevel};
use plain::Plain;
use tcpstates::*;

const TCP_STATES: [&'static str; 14] = [
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NEW_SYN_RECV",
    "UNKNOWN",
];

unsafe impl Plain for tcpstates_bss_types::event {}

#[derive(Debug, Clone, Copy, Parser)]
struct Command {
    #[clap(short, long)]
    verbose: bool,

    #[clap(short, long, default_value = "0")]
    target_family: i16,
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

    let mut skel_builder = TcpstatesSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // 读取字节码
    let mut open_skel = skel_builder.open()?;

    match opts.target_family {
        2 => open_skel.rodata().target_family = 2,
        10 => open_skel.rodata().target_family = 10,
        _ => {}
    }

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    println!(
        "{:<24} {:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11} -> {:11} {}",
        "SKADDR",
        "PID",
        "COMM",
        "IP",
        "LADDR",
        "LPORT",
        "RADDR",
        "RPORT",
        "OLDSTATE",
        "NEWSTATE",
        "MS"
    );

    let perf = PerfBufferBuilder::new(&skel.maps_mut().events())
        .sample_cb(|_cpu, data: &[u8]| {
            let mut event = tcpstates_bss_types::event::default();
            plain::copy_from_bytes(&mut event, data).expect("data length not match");

            let task = std::str::from_utf8(&event.task)
                .expect("parse str error")
                .trim_end_matches(char::from(0));

            let lport = b2l_u16(event.sport);
            let rport = b2l_u16(event.dport);

            match event.family {
                2 => unsafe {
                    let saddr: u32 = b2l_u32(event.__anon_1.saddr_v4);
                    let daddr: u32 = b2l_u32(event.__anon_2.daddr_v4);

                    println!(
                        "{:<24} {:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11} -> {:11} {}",
                        event.skaddr,
                        event.tgid,
                        task,
                        event.family,
                        Ipv4Addr::from(saddr),
                        lport,
                        Ipv4Addr::from(daddr),
                        rport,
                        TCP_STATES[event.oldstate as usize],
                        TCP_STATES[event.newstate as usize],
                        event.delta_us / 1000,
                    )
                },
                10 => unsafe {
                    let saddr: u128 = b2l_u128_array(&event.__anon_1.saddr_v6);
                    let daddr: u128 = b2l_u128_array(&event.__anon_2.daddr_v6);

                    println!(
                        "{:16} {:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11} -> {:11} {:<}",
                        event.skaddr,
                        event.tgid,
                        task,
                        event.family,
                        Ipv6Addr::from(saddr),
                        lport,
                        Ipv6Addr::from(daddr),
                        rport,
                        TCP_STATES[event.oldstate as usize],
                        TCP_STATES[event.newstate as usize],
                        event.delta_us / 1000,
                    )
                },
                _ => {}
            }
        })
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
