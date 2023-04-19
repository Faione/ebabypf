// 以模块的形式将字节码引入到程序中
mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}

use std::{
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use hello::*;
use libbpf_rs::PrintLevel;

#[derive(Debug, Clone, Copy, Parser)]
struct Command {
    #[clap(short, long)]
    verbose: bool,
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

    let mut skel_builder = HelloSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // 读取字节码
    let open_skel = skel_builder.open()?;

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    println!(
        "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs."
    );

    // 键盘事件监听
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("error while setting ctrlc handler");

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        std::thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}
