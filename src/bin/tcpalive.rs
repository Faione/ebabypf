// 以模块的形式将字节码引入到程序中
mod tcpalive {
    include!(concat!(env!("OUT_DIR"), "/tcpalive.skel.rs"));
}

use std::{
    env,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use clap::Parser;
use ebabypf::{b2l_u128_array, b2l_u32};
use libbpf_rs::{Map, MapFlags, PrintLevel};
use plain::Plain;
use tcpalive::*;
use tokio::{select, signal};

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

unsafe impl Plain for tcpalive_bss_types::event {}

#[derive(Debug, Clone, Copy, Parser)]
struct Command {
    #[clap(short, long)]
    verbose: bool,
}

fn init_log() {
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

fn print_connections(connections: &Map) {
    let mut line = String::from(&format!(
        "{:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11}\n",
        "PID", "COMM", "IP", "LADDR", "LPORT", "RADDR", "RPORT", "STATE"
    ));

    connections.keys().for_each(|key| {
        if let Ok(Some(data)) = connections.lookup(&key, MapFlags::ANY) {
            let mut event = tcpalive_bss_types::event::default();
            plain::copy_from_bytes(&mut event, &data).expect("data not long enough");

            let task = std::str::from_utf8(&event.task)
                .expect("parse error")
                .trim_end_matches(char::from(0));

            match event.family {
                2 => unsafe {
                    let saddr: u32 = b2l_u32(event.__anon_1.saddr_v4);
                    let daddr: u32 = b2l_u32(event.__anon_2.daddr_v4);
                    line.push_str(&format!(
                        "{:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11}\n",
                        event.tgid,
                        task,
                        event.family,
                        Ipv4Addr::from(saddr),
                        event.sport,
                        Ipv4Addr::from(daddr),
                        event.dport,
                        TCP_STATES[event.newstate as usize],
                    ));
                },
                10 => unsafe {
                    let saddr: u128 = b2l_u128_array(&event.__anon_1.saddr_v6);
                    let daddr: u128 = b2l_u128_array(&event.__anon_2.daddr_v6);
                    line.push_str(&format!(
                        "{:<7} {:16} {:<2} {:<26} {:<5} {:<26} {:<5} {:11}\n",
                        event.tgid,
                        task,
                        event.family,
                        Ipv6Addr::from(saddr),
                        event.sport,
                        Ipv6Addr::from(daddr),
                        event.dport,
                        TCP_STATES[event.newstate as usize],
                    ));
                },
                _ => {
                    return;
                }
            }
        }
    });

    // 将光标移动到第一行第一列并打印所有内容
    print!("\x1B[2J\x1B[1;1H{}", line);

    // 强制刷新缓冲区
    std::io::stdout().flush().expect("flush falied");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log();
    let opts = Command::parse();

    let mut skel_builder = TcpaliveSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // 读取字节码
    let open_skel = skel_builder.open()?;

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    let maps = skel.maps();
    let connetions = maps.conns();

    loop {
        select! {
            _ = signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {
                print_connections(connetions);
            }
        }
    }

    Ok(())
}
