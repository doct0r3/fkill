#![no_std]
#![no_main]
mod bindings_process_fork;

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_log_ebpf::info;
use bindings_process_fork::trace_event_raw_sched_process_fork;
use fkill_common::NewClone;

#[map]
static mut EVENT_CHANNEL: RingBuf = RingBuf::with_byte_size(0x100, 0);

#[tracepoint]
pub fn handle_sched_sched_process_fork(ctx: TracePointContext) -> u32 {
    let args = unsafe {
        ctx.read_at::<trace_event_raw_sched_process_fork>(0)
            .unwrap()
    };
    unsafe {
        if let Some(mut buf) = EVENT_CHANNEL.reserve::<NewClone>(0) {
            info!(
                &ctx,
                "Spawning child:parent:{},child:{}", args.parent_pid, args.child_pid
            );
            let ptr = buf.as_mut_ptr();
            (*ptr).child_pid = args.child_pid;
            (*ptr).parent_pid = args.parent_pid;
            buf.submit(0);
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
