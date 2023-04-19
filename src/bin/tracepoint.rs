// 以模块的形式将字节码引入到程序中
mod tracepoint {
    include!(concat!(env!("OUT_DIR"), "/tracepoint.skel.rs"));
}

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Ok;
use clap::Parser;
use libbpf_rs::PrintLevel;
use tracepoint::*;

#[derive(Debug, Parser)]
struct Command {
    #[clap(short = 'p', long = "pid", default_value = "0")]
    pid: i32,
}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        _ => println!("{}", msg),
    }
}
fn main() -> anyhow::Result<()> {
    let ops = Command::parse();
    libbpf_rs::set_print(Some((PrintLevel::Debug, print_to_log)));
    let skel_builder = TracepointSkelBuilder::default();
    // 读取字节码
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().pid_target = ops.pid;

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
