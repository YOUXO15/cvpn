use clap::Parser;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_ushort};
use std::sync::{Mutex, OnceLock};
use tun2proxy::{Args, CancellationToken, general_run_async};

static ACTIVE_TOKEN: OnceLock<Mutex<Option<CancellationToken>>> = OnceLock::new();

fn token_slot() -> &'static Mutex<Option<CancellationToken>> {
    ACTIVE_TOKEN.get_or_init(|| Mutex::new(None))
}

/// Runs one tun2proxy instance on the calling thread until `TunnelProxyStop`
/// cancels it. Unlike tun2proxy's generic C wrapper, this adapter never calls
/// `exit`, which is required for a reusable iOS Network Extension process.
///
/// # Safety
/// `cli_args` must point to a valid NUL-terminated UTF-8 string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn TunnelProxyRun(
    cli_args: *const c_char,
    tun_mtu: c_ushort,
    packet_information: bool,
) -> c_int {
    if cli_args.is_null() {
        return -10;
    }
    let raw = match unsafe { CStr::from_ptr(cli_args) }.to_str() {
        Ok(value) => value,
        Err(_) => return -11,
    };
    let arguments = match shlex::split(raw) {
        Some(value) => value,
        None => return -12,
    };
    let parsed = match Args::try_parse_from(arguments) {
        Ok(value) => value,
        Err(_) => return -13,
    };

    let token = CancellationToken::new();
    {
        let mut slot = match token_slot().lock() {
            Ok(value) => value,
            Err(_) => return -14,
        };
        if slot.is_some() {
            return -15;
        }
        *slot = Some(token.clone());
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(_) => {
            if let Ok(mut slot) = token_slot().lock() {
                slot.take();
            }
            return -16;
        }
    };

    let result = runtime.block_on(general_run_async(
        parsed,
        tun_mtu,
        packet_information,
        token,
    ));
    if let Ok(mut slot) = token_slot().lock() {
        slot.take();
    }
    if result.is_ok() { 0 } else { -17 }
}

#[unsafe(no_mangle)]
pub extern "C" fn TunnelProxyStop() -> c_int {
    let mut slot = match token_slot().lock() {
        Ok(value) => value,
        Err(_) => return -20,
    };
    match slot.take() {
        Some(token) => {
            token.cancel();
            0
        }
        None => -21,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn TunnelProxyIsRunning() -> bool {
    token_slot()
        .lock()
        .map(|slot| slot.is_some())
        .unwrap_or(false)
}
