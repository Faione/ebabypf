// 以模块的形式将字节码引入到程序中
mod hardirqs {
    include!(concat!(env!("OUT_DIR"), "/hardirqs.skel.rs"));
}

use std::{
    env,
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use hardirqs::*;
use libbpf_rs::{Map, MapFlags, PrintLevel};
use plain::Plain;

unsafe impl Plain for hardirqs_bss_types::info {}
unsafe impl Plain for hardirqs_bss_types::irq_key {}

#[derive(Debug, Clone, Copy, Parser)]
struct Command {
    #[clap(short, long)]
    verbose: bool,

    #[clap(short, long)]
    ns: bool,
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

fn print_mp(mp: &Map) {
    let mut line = String::new();
    line.push_str(&format!("{:20} {:10} {:20}\n", "IRQ", "COUNT", "SUM"));

    let mut ikey = hardirqs_bss_types::irq_key::default();
    let mut info = hardirqs_bss_types::info::default();
    mp.keys().for_each(|key| {
        if let Ok(Some(data)) = mp.lookup(&key, MapFlags::ANY) {
            plain::copy_from_bytes(&mut ikey, &key).expect("paring failed");
            plain::copy_from_bytes(&mut info, &data).expect("paring failed");

            let irq_str = std::str::from_utf8(&ikey.name)
                .expect("paring str failed")
                .trim_end_matches(char::from(0));

            line.push_str(&format!(
                "{:20} {:<10} {:<20}\n",
                irq_str, info.count, info.sum
            ));
        }
    });

    // 将光标移动到第一行第一列并打印所有内容
    print!("\x1B[2J\x1B[1;1H{}", line);

    // 强制刷新缓冲区
    std::io::stdout().flush().expect("flush falied");
}

fn main() -> anyhow::Result<()> {
    init_libbpf_log();
    let opts = Command::parse();

    let mut skel_builder = HardirqsSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // 读取字节码
    let mut open_skel = skel_builder.open()?;
    if opts.ns {
        open_skel.rodata().enable_ns = true;
    }

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    let maps = skel.maps();
    let infos = maps.infos();

    // 键盘事件监听
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("error while setting ctrlc handler");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
        print_mp(infos);
    }

    Ok(())
}
