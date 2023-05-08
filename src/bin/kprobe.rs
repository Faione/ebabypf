mod kprobe {
    include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

use kprobe::*;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skel_builder = KprobeSkelBuilder::default();

    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load().unwrap();

    skel.attach().unwrap();

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
