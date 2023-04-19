mod tcpv4connect {
    include!(concat!(env!("OUT_DIR"), "/tcpv4connect.skel.rs"));
}

use clap::Parser;
use ebabypf::*;
use libbpf_rs::{PerfBufferBuilder, PrintLevel};
use plain::Plain;
use std::{env, net::Ipv4Addr, time::Duration};
use tcpv4connect::*;

unsafe impl Plain for tcpv4connect_bss_types::event {}

#[derive(Debug, Parser)]
struct Command {
    /// Process PID to trace
    #[clap(short = 'p', long, default_value = "0")]
    pid: i32,

    /// Process UID to trace
    #[clap(short = 'u', long, default_value = "0")]
    uid: u32,

    /// Comma-separated list of destination ports to trace
    #[clap(short = 'P', long, default_value = "")]
    port: String,
}

fn parse_ports(cmd: &Command) -> (usize, Option<Vec<u16>>) {
    if cmd.port == "" {
        return (0, None);
    }

    let ports: Vec<u16> = cmd
        .port
        .split(';')
        .map(|s| {
            let n: u16 = s.parse().unwrap();
            n
        })
        .collect();

    (if ports.len() > 64 { 64 } else { ports.len() }, Some(ports))
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = tcpv4connect_bss_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer was too short");

    let saddr = b2l_u32(event.saddr_v4);
    let daddr = b2l_u32(event.daddr_v4);
    let sport = b2l_u16(event.sport);
    let dport = b2l_u16(event.dport);

    // cmd长度总是 16, 无效区域由`\0`填充
    // 格式化输出中填充 cmd 长度为目标长度，但是输出时会忽略`\0`，导致输出与预期不符
    let cmd = std::str::from_utf8(&event.task)
        .expect("error while parsing task")
        .trim_end_matches(char::from(0));

    // rust 中, 字符串总是向左对齐，数字总是向右对齐，使用 `<`, `^`, `>` 来进行手动控制
    println!(
        "{:<9} {:<5} {:16} {:16} {:<5} {:16} {:<5}",
        event.pid,
        event.uid,
        cmd,
        Ipv4Addr::from(saddr),
        sport,
        Ipv4Addr::from(daddr),
        dport,
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("lost {count} events on cpu {cpu}")
}

fn print_banner() {
    println!(
        "{:9} {:5} {:16} {:16} {:5} {:16} {:5}",
        "PID", "UID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT"
    );
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
    let opts = Command::parse();

    // 设置日志
    init_libbpf_log();

    // 加载 ebpf 程序
    let skel_builder = Tcpv4connectSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    // 设置参数
    open_skel.rodata().filter_pid = opts.pid;
    open_skel.rodata().filter_uid = opts.uid;

    let (nports, ports_warp) = parse_ports(&opts);
    if let Some(ports) = ports_warp {
        for i in 0..nports {
            open_skel.rodata().filter_ports[i] = l2b_u16(ports[i]) as i32;
        }
        open_skel.rodata().filter_ports_len = nports as i32;
    }

    let mut skel = open_skel.load().unwrap();
    skel.attach().unwrap();

    // 创建event管道监听输出
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    print_banner();
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
