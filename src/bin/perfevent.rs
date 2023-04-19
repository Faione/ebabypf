// 以模块的形式将字节码引入到程序中
mod perfevent {
    include!(concat!(env!("OUT_DIR"), "/perfevent.skel.rs"));
}

use std::{env, time::Duration};

use chrono::Utc;
use libbpf_rs::{PerfBufferBuilder, PrintLevel};
use perfevent::*;
use plain::Plain;

unsafe impl Plain for perfevent_bss_types::event {}

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
    let skel_builder = PerfeventSkelBuilder::default();
    // 读取字节码
    let open_skel = skel_builder.open()?;

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    println!(
        "{:20} {:8} {:8} {:8} {:20}",
        "TIME", "PID", "PPID", "UID", "COMM"
    );
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(move |_cpu: i32, data: &[u8]| {
            let mut event = perfevent_bss_types::event::default();
            plain::copy_from_bytes(&mut event, data).expect("data buffer was too short");

            let current_time = Utc::now();
            let cmd = std::str::from_utf8(&event.comm)
                .expect("")
                .trim_end_matches(char::from(0));

            println!(
                "{:20} {:<8} {:<8} {:<8} {:20}",
                current_time.format("%d/%m/%Y %H:%M"),
                event.pid,
                event.ppid,
                event.uid,
                cmd
            )
        })
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
