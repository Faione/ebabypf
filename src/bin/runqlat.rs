// 以模块的形式将字节码引入到程序中
mod runqlat {
    include!(concat!(env!("OUT_DIR"), "/runqlat.skel.rs"));
}

use std::{env, fmt::Error, str::FromStr, time::Duration};

use anyhow::bail;
use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;

use libbpf_rs::{Map, MapFlags, PrintLevel};
use plain::Plain;
use runqlat::*;

unsafe impl Plain for runqlat_bss_types::hist {}

#[derive(Debug, Clone, Copy)]
enum PerMode {
    PROCESS,
    THREAD,
    PIDNS,
}

fn bump_memlock_rlimit() -> anyhow::Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

impl FromStr for PerMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "process" => Ok(PerMode::PROCESS),
            "thread" => Ok(PerMode::THREAD),
            "pidns" => Ok(PerMode::PIDNS),
            _ => Err(Error),
        }
    }
}

#[derive(Debug, Parser)]
struct Command {
    #[clap(short, long, default_value = "process")]
    per_mode: PerMode,

    #[clap(short, long, default_value = "false")]
    ms: bool,

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

fn print_hist(mp: &Map, per_mode: PerMode) {
    mp.keys().for_each(|key| {
        if let Ok(Some(data)) = mp.lookup(&key, MapFlags::ANY) {
            let mut entry = runqlat_bss_types::hist::default();
            plain::copy_from_bytes(&mut entry, &data).expect("data is not long enough");

            let pid = LittleEndian::read_u32(&key);

            let cmd = std::str::from_utf8(&entry.comm)
                .expect("error while parsing str")
                .trim_matches(char::from('0'));

            match per_mode {
                PerMode::PIDNS => print!("pidns = {} {}", pid, cmd),
                PerMode::THREAD => print!("pid = {} {}", pid, cmd),
                PerMode::PROCESS => print!("tgid = {} {}", pid, cmd),
            }

            (0..26).for_each(|index: usize| {
                print!(" {}", entry.bucket[index]);
            });

            print!("\n")
        };
    });

    mp.keys().for_each(|key| {
        mp.delete(&key).expect("fail to clean map");
    });
}

fn main() -> anyhow::Result<()> {
    init_libbpf_log();
    let opts = Command::parse();

    let mut skel_builder = RunqlatSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    // 读取字节码
    let mut open_skel = skel_builder.open()?;

    // 设置flag
    match opts.per_mode {
        PerMode::PIDNS => open_skel.rodata().per_pidns = true,
        PerMode::THREAD => open_skel.rodata().per_thread = true,
        PerMode::PROCESS => open_skel.rodata().per_process = true,
    }
    if opts.ms {
        open_skel.rodata().ms = true;
    }

    // 加载ebpf程序到内核
    let mut skel = open_skel.load()?;

    // attach ebpf程序到挂载点
    skel.attach()?;

    let maps = skel.maps();
    let hists = maps.hists();

    loop {
        std::thread::sleep(Duration::from_secs(1));
        print_hist(hists, opts.per_mode);
    }
}
