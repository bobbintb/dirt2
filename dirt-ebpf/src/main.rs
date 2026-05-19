#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

use dirt_common::{Event, EventType, ShareName};

#[map]
static mut WHITELIST: HashMap<ShareName, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
static mut CALLS: HashMap<u64, Event> = HashMap::with_max_entries(1024, 0);

#[map]
static mut SCRATCH: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut SHARE_SCRATCH: PerCpuArray<ShareName> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn uprobe_unlink(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_unlink called");
    match try_uprobe_handler(ctx, EventType::Unlink) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn uprobe_create(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_create called");
    match try_uprobe_handler(ctx, EventType::Create) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn uprobe_rename(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_rename called");
    match try_uprobe_handler(ctx, EventType::Rename) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_handler(ctx: ProbeContext, event_type: EventType) -> Result<u32, u32> {
    unsafe {
        let event = (*(&raw mut SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;
        (*event).event = event_type;

        match event_type {
            EventType::Unlink | EventType::Create => {
                let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
                bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut (*event).src_path)
                    .map_err(|e| e as u32)?;
                // Explicitly clear tgt_path to prevent stale data
                (*event).tgt_path[0] = 0;
            }
            EventType::Rename => {
                let src_path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
                let tgt_path_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
                bpf_probe_read_user_str_bytes(src_path_ptr as *const u8, &mut (*event).src_path)
                    .map_err(|e| e as u32)?;
                bpf_probe_read_user_str_bytes(tgt_path_ptr as *const u8, &mut (*event).tgt_path)
                    .map_err(|e| e as u32)?;
            }
        }

        let pid_tgid = bpf_get_current_pid_tgid();
        (*(&raw mut CALLS)).insert(&pid_tgid, &*event, 0).map_err(|e| e as u32)?;
    }
    Ok(0)
}

#[uretprobe]
pub fn uretprobe_unlink(ctx: RetProbeContext) -> u32 {
    match try_uretprobe_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn uretprobe_create(ctx: RetProbeContext) -> u32 {
    match try_uretprobe_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn uretprobe_rename(ctx: RetProbeContext) -> u32 {
    match try_uretprobe_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_share_name(path: &[u8], share: &mut ShareName) -> Result<(), u32> {
    // Clear the buffer first to ensure no stale data
    for byte in share.iter_mut() {
        *byte = 0;
    }

    let mut i = 0;
    let mut j = 0;

    // Skip leading '/'
    if path.get(0) == Some(&b'/') {
        i = 1;
    }

    // Copy until next '/' or null terminator or end of path
    while i < path.len() {
        let c = match path.get(i) {
            Some(&c) => c,
            None => break,
        };
        if c == 0 || c == b'/' {
            break;
        }
        // Check bounds before writing
        if j < 255 {
            share[j] = c;
            j += 1;
        } else {
            break;
        }
        i += 1;
    }

    Ok(())
}


fn try_uretprobe_handler(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let event_ptr = unsafe { (*(&raw mut CALLS)).get(&pid_tgid) };

    let event = event_ptr.ok_or(1u32)?;
    let ret = ctx.ret::<i32>().ok_or(1u32)?;

    if ret == 0 {
        unsafe {
            let share_name_buf = (*(&raw mut SHARE_SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;

            // Check the source path first.
            get_share_name(&(*event).src_path, &mut *share_name_buf)?;
            if (*(&raw mut WHITELIST)).get(&*share_name_buf).is_some() {
                let _ = (*(&raw mut EVENTS)).output(&*event, 0);
            } else if matches!((*event).event, EventType::Rename) {
                // If it's a rename event and source wasn't whitelisted, check the target path.
                get_share_name(&(*event).tgt_path, &mut *share_name_buf)?;
                if (*(&raw mut WHITELIST)).get(&*share_name_buf).is_some() {
                    let _ = (*(&raw mut EVENTS)).output(&*event, 0);
                }
            }
        }
    }

    // Always remove the entry from the map after processing
    unsafe {
        let _ = (*(&raw mut CALLS)).remove(&pid_tgid);
    }

    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";