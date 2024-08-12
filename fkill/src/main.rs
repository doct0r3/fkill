extern crate hexplay;

use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::{App, Arg};
use fkill_common::NewClone;
use log::debug;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashSet;
use std::mem::{self, size_of};
use std::ops::Deref;
use std::process::{self};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let matches = App::new("fkill")
        .version("1.0")
        .author("By Dr.3")
        .about("fork kill")
        .arg(
            Arg::with_name("pid")
                .short('p')
                .long("pid")
                .takes_value(true)
                .help("filter specific pid")
                .required(true),
        )
        .get_matches();
    let pid = match matches.value_of("pid") {
        Some(pid_str) => pid_str.parse().expect("pid must be a number"),
        None => i32::MAX,
    };

    env_logger::init();
    

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/fkill"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        panic!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut TracePoint = bpf
        .program_mut("handle_sched_sched_process_fork")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    let channel = bpf
        .take_map("EVENT_CHANNEL")
        .expect("failed to take event channel");
    let channel = RingBuf::try_from(channel).unwrap();
    let mut async_channel = AsyncFd::new(channel)?;
    let mut pid_store = HashSet::new();
    pid_store.insert(pid);
    loop {
        let mut lock = async_channel.readable_mut().await?;
        let entry = lock.get_inner_mut().next();
        if entry.is_none() {
            drop(entry);
            lock.clear_ready();
            continue;
        }

        let buf: [u8; size_of::<NewClone>()] = entry
            .unwrap()
            .deref()
            .try_into()
            .expect("Deserialization Failed!");
        let data: NewClone = unsafe { mem::transmute(buf) };

        let parent = data.parent_pid;
        let child = data.child_pid;
        if parent as u32 == process::id() {
            continue;
        }
        println!("Spawning child:parent:{},child:{}", parent, child);
        let need_kill = if pid_store.contains(&parent) {
            true
        } else {
            false
        };
        if need_kill {
            pid_store.insert(child);
            println!("Stopping child:{}", child);
            kill(Pid::from_raw(child), Signal::SIGSTOP)?;
        }
    }
}
