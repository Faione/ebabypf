// 以模块的形式将字节码引入到程序中
mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}

use std::env;

use clap::Parser;
use hello::*;
use libbpf_rs::PrintLevel;
use tokio::signal;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    // 退出信号监听
    match signal::ctrl_c().await {
        Ok(()) => {}
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }
    Ok(())
}
