// 以模块的形式将字节码引入到程序中
mod uprobe {
    include!(concat!(env!("OUT_DIR"), "/uprobe.skel.rs"));
}

use libbpf_rs::PrintLevel;
use tokio::signal;
use uprobe::*;

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        _ => println!("{}", msg),
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    libbpf_rs::set_print(Some((PrintLevel::Debug, print_to_log)));
    let skel_builder = UprobeSkelBuilder::default();
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
