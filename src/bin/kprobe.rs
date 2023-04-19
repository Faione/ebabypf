mod kprobe {
    include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Ok;
use kprobe::*;

fn main() -> anyhow::Result<()> {
    let skel_builder = KprobeSkelBuilder::default();

    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load().unwrap();

    skel.attach().unwrap();

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
