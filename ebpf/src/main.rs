#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

#[classifier]
pub fn dnstop(ctx: TcContext) -> i32 {
    match try_dnstop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dnstop(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
