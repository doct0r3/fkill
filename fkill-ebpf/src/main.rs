#![no_std]
#![no_main]
mod bindings_process_exec;
mod bindings_process_fork;

use aya_ebpf::helpers;
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_log_ebpf::{error, info};
use bindings_process_exec::trace_event_raw_sched_process_exec;
use bindings_process_fork::trace_event_raw_sched_process_fork;
use fkill_common::{NewClone, PidBuf};

#[map]
static mut EVENT_CHANNEL: RingBuf = RingBuf::with_byte_size(0x100, 0);

#[map]
static mut PID_STORE_BUF: RingBuf = RingBuf::with_byte_size(40, 0);

#[inline(always)]
fn stop_current() {
    unsafe {
        helpers::bpf_send_signal_thread(19 /* SIGSTOP */);
    }
}

#[tracepoint]
pub fn handle_sched_sched_process_fork(ctx: TracePointContext) -> u32 {
    let args = unsafe {
        ctx.read_at::<trace_event_raw_sched_process_fork>(0)
            .unwrap()
    };
    info!(
        &ctx,
        "Spawning child:parent:{},child:{}", args.parent_pid, args.child_pid
    );

    let mut need_stop = false;
    unsafe {
        if let Some(mut buf) = EVENT_CHANNEL.reserve::<NewClone>(0) {
            // info!(
            //     &ctx,
            //     "Current Pid:{}",
            //     (helpers::bpf_get_current_pid_tgid() & 0xFFFFFFFF) as i32
            // );
            let ptr = buf.as_mut_ptr();
            let parent_pid = args.parent_pid;
            (*ptr).child_pid = args.child_pid;
            (*ptr).parent_pid = parent_pid;
            if parent_pid == 25355 {
                // TODO:Read from userspace
                need_stop = true;
                info!(&ctx, "Stopping child:{}", args.child_pid);
            }

            buf.submit(0);
        }

        if let Some(mut pids) = PID_STORE_BUF.reserve::<PidBuf>(0) {
            let pids_ptr = pids.as_mut_ptr();
            let mut has_empty_slot = false;
            for i in 1..10 {
                // info!(&ctx, "Checking Pid Slot:{}", (*pids_ptr).pids[i]);
                if (*pids_ptr).pids[i] == 0 && need_stop {
                    (*pids_ptr).pids[i] = args.child_pid;
                    info!(&ctx, "Pending to stop child:{}", args.child_pid);
                    has_empty_slot = true;
                    break;
                }
            }
            if !has_empty_slot && need_stop {
                error!(&ctx, " Pid Slot has Drained.");
            }
            pids.submit(0);
        }
    }
    0
}

#[tracepoint]
pub fn handle_sched_sched_process_exec(ctx: TracePointContext) -> u32 {
    let args = unsafe {
        ctx.read_at::<trace_event_raw_sched_process_exec>(0)
            .unwrap()
    };
    let cur_pid = args.pid;
    info!(&ctx, "Current exec:{}", cur_pid);
    info!(
        &ctx,
        "Current Pid:{}",
        (helpers::bpf_get_current_pid_tgid() & 0xFFFFFFFF) as i32
    );
    unsafe {
        if let Some(pids) = PID_STORE_BUF.reserve::<PidBuf>(0) {
            let pids_ptr = pids.as_ptr();
            for i in 1..10 {
                if (*pids_ptr).pids[i] == cur_pid {
                    info!(&ctx, "Stopping current:{}", cur_pid);
                    stop_current();
                    break;
                }
            }
            pids.submit(0);
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
