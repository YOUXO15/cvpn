use std::ffi::CString;

fn main() {
    let command = std::env::args().collect::<Vec<_>>().join(" ");
    let command = CString::new(command).expect("probe arguments contain NUL");
    let result = unsafe {
        tunnel_proxy_shim::TunnelProxyRun(command.as_ptr(), 1_360, true)
    };
    if result != 0 {
        std::process::exit(1);
    }
}
