//! `XCL_NETWORK=0`: the title runs as on a console without a network. Its WinHTTP requests and
//! its sockets fail as they do there (name not resolved / network unreachable); nothing is
//! answered in a server's place. Loopback connections stay (titles make socket pairs), and so
//! do lookups of the local names (none, this machine's, localhost). Only
//! the title's own imports are concerned (the game's exe and DLLs); off by default.
//!
//! For titles under bring-up: a crash reporter otherwise uploads a memory dump of the process
//! on every crash.
//!
//! The title's imports are not the only way out: a retail game's crash reporter reached the
//! system's WinHTTP another way and uploaded a 21.5 MB minidump with `XCL_NETWORK=0` (#305).
//! So the same refusals are also hooked into the system's own winhttp / wininet / ws2_32
//! (`install_system_hooks`): whatever finds those functions – an import, GetProcAddress, a DLL
//! of the title's – gets no network. What goes through (loopback, local names) calls the
//! original through the hook's trampoline.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::SetLastError;

pub const NETOFF: &str = "xcl-netoff.dll";

const ERROR_WINHTTP_NAME_NOT_RESOLVED: u32 = 12007;
const WSAENETUNREACH: i32 = 10051;
const WSAHOST_NOT_FOUND: i32 = 11001;
const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
const WSAID_CONNECTEX: [u8; 16] = [
    0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46,
    0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e,
];

#[link(name = "ws2_32", kind = "raw-dylib")]
extern "system" {
    #[link_name = "connect"]
    fn real_connect(s: usize, name: *const u8, len: i32) -> i32;
    #[link_name = "WSAIoctl"]
    fn real_wsai_ioctl(
        s: usize,
        code: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        completion: *const c_void,
    ) -> i32;
    #[link_name = "sendto"]
    fn real_sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32;
    #[link_name = "WSASendMsg"]
    fn real_wsa_send_msg(s: usize, msg: *const c_void, flags: u32, sent: *mut u32, ov: *mut c_void, cb: *const c_void) -> i32;
    #[link_name = "WSASendTo"]
    fn real_wsa_send_to(s: usize, bufs: *const c_void, n: u32, sent: *mut u32, flags: u32, to: *const u8, tolen: i32, ov: *mut c_void, cb: *const c_void) -> i32;
    fn WSASetLastError(e: i32);
    #[link_name = "getaddrinfo"]
    fn real_getaddrinfo(node: *const u8, service: *const u8, hints: *const c_void, out: *mut *mut c_void) -> i32;
    #[link_name = "GetAddrInfoW"]
    fn real_getaddrinfo_w(node: *const u16, service: *const u16, hints: *const c_void, out: *mut *mut c_void) -> i32;
    #[link_name = "gethostname"]
    fn real_gethostname(name: *mut u8, len: i32) -> i32;
}

/// A name that resolves without a network: none (the local addresses), this machine's own
/// name, localhost – a console without a network still answers these (a retail game asks for
/// its own name and none at start).
fn local_name(name: &str) -> bool {
    if name.is_empty() || name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return true;
    }
    let mut buf = [0u8; 256];
    let own = unsafe { real_gethostname(buf.as_mut_ptr(), buf.len() as i32) } == 0;
    own && {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&buf[..n]).is_ok_and(|h| h.eq_ignore_ascii_case(name))
    }
}

pub fn enabled() -> bool {
    std::env::var("XCL_NETWORK").is_ok_and(|v| v.trim() == "0")
}

/// (name, address, ws2_32 ordinal – 0: imported by name only)
fn table() -> Vec<(&'static str, usize, u16)> {
    vec![
        ("WinHttpSendRequest", send_request as *const () as usize, 0),
        ("connect", connect as *const () as usize, 4),
        ("sendto", sendto as *const () as usize, 20),
        ("gethostbyname", gethostbyname as *const () as usize, 52),
        ("WSAConnect", wsa_connect as *const () as usize, 0),
        ("WSASendTo", wsa_send_to as *const () as usize, 0),
        ("getaddrinfo", getaddrinfo as *const () as usize, 0),
        ("GetAddrInfoW", getaddrinfo_w as *const () as usize, 0),
        ("GetAddrInfoExW", getaddrinfo_ex as *const () as usize, 0),
        ("WSAConnectByList", wsa_connect_by_list as *const () as usize, 0),
    ]
}

pub fn exports() -> Vec<(&'static str, usize)> {
    table().into_iter().map(|(n, a, _)| (n, a)).collect()
}

pub fn ordinals() -> Vec<(u16, &'static str)> {
    table().into_iter().filter(|t| t.2 != 0).map(|(n, _, o)| (o, n)).collect()
}

fn note(what: &str) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    if N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 16 {
        crate::xlog_info!("XCL_NETWORK=0: {what} fails (no network)");
    }
}

/// 127.0.0.0/8 or ::1 (sockaddr_in / sockaddr_in6), or 127.0.0.0/8 as an IPv4-mapped address
/// (::ffff:127.x.x.x – how a socket for both IPv6 and IPv4 names an IPv4 host)
unsafe fn loopback(name: *const u8, len: i32) -> bool {
    if name.is_null() || len < 8 {
        return false;
    }
    match (name as *const u16).read_unaligned() {
        2 => *name.add(4) == 127,
        23 if len >= 24 => {
            let a = std::slice::from_raw_parts(name.add(8), 16);
            (a[..15].iter().all(|&b| b == 0) && a[15] == 1) || (a[..10].iter().all(|&b| b == 0) && a[10..12] == [0xff, 0xff] && a[12] == 127)
        }
        _ => false,
    }
}

unsafe fn unreachable_net(what: &str) -> i32 {
    note(what);
    WSASetLastError(WSAENETUNREACH);
    -1
}

/// the originals of the system functions hooked (`install_system_hooks`; 0: not hooked – the
/// linked import is the original)
static O_CONNECT: AtomicUsize = AtomicUsize::new(0);
static O_SENDTO: AtomicUsize = AtomicUsize::new(0);
static O_WSA_SEND_MSG: AtomicUsize = AtomicUsize::new(0);
static O_WSA_SEND_TO: AtomicUsize = AtomicUsize::new(0);
static O_GETADDRINFO: AtomicUsize = AtomicUsize::new(0);
static O_GETADDRINFO_W: AtomicUsize = AtomicUsize::new(0);
static O_WSAIOCTL: AtomicUsize = AtomicUsize::new(0);
static O_CONNECT_EX: AtomicUsize = AtomicUsize::new(0);
/// trampolines of hooks whose original is never called
static O_UNUSED: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];

unsafe fn orig_connect(s: usize, name: *const u8, len: i32) -> i32 {
    match O_CONNECT.load(Ordering::Acquire) {
        0 => real_connect(s, name, len),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(usize, *const u8, i32) -> i32>(f)(s, name, len),
    }
}

unsafe fn orig_sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32 {
    match O_SENDTO.load(Ordering::Acquire) {
        0 => real_sendto(s, buf, len, flags, to, tolen),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(usize, *const u8, i32, i32, *const u8, i32) -> i32>(f)(s, buf, len, flags, to, tolen),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn orig_wsai_ioctl(
    s: usize,
    code: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
    returned: *mut u32,
    overlapped: *mut c_void,
    completion: *const c_void,
) -> i32 {
    let f = O_WSAIOCTL.load(Ordering::Acquire);
    let f = if f == 0 { real_wsai_ioctl as usize } else { f };
    std::mem::transmute::<
        usize,
        unsafe extern "system" fn(usize, u32, *const c_void, u32, *mut c_void, u32, *mut u32, *mut c_void, *const c_void) -> i32,
    >(f)(s, code, in_buf, in_len, out_buf, out_len, returned, overlapped, completion)
}

unsafe fn orig_wsa_send_msg(s: usize, msg: *const c_void, flags: u32, sent: *mut u32, ov: *mut c_void, cb: *const c_void) -> i32 {
    match O_WSA_SEND_MSG.load(Ordering::Acquire) {
        0 => real_wsa_send_msg(s, msg, flags, sent, ov, cb),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(usize, *const c_void, u32, *mut u32, *mut c_void, *const c_void) -> i32>(f)(s, msg, flags, sent, ov, cb),
    }
}

unsafe fn orig_wsa_send_to(s: usize, bufs: *const c_void, n: u32, sent: *mut u32, flags: u32, to: *const u8, tolen: i32, ov: *mut c_void, cb: *const c_void) -> i32 {
    match O_WSA_SEND_TO.load(Ordering::Acquire) {
        0 => real_wsa_send_to(s, bufs, n, sent, flags, to, tolen, ov, cb),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(usize, *const c_void, u32, *mut u32, u32, *const u8, i32, *mut c_void, *const c_void) -> i32>(f)(s, bufs, n, sent, flags, to, tolen, ov, cb),
    }
}

unsafe fn orig_getaddrinfo(node: *const u8, service: *const u8, hints: *const c_void, out: *mut *mut c_void) -> i32 {
    match O_GETADDRINFO.load(Ordering::Acquire) {
        0 => real_getaddrinfo(node, service, hints, out),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(*const u8, *const u8, *const c_void, *mut *mut c_void) -> i32>(f)(node, service, hints, out),
    }
}

unsafe fn orig_getaddrinfo_w(node: *const u16, service: *const u16, hints: *const c_void, out: *mut *mut c_void) -> i32 {
    match O_GETADDRINFO_W.load(Ordering::Acquire) {
        0 => real_getaddrinfo_w(node, service, hints, out),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(*const u16, *const u16, *const c_void, *mut *mut c_void) -> i32>(f)(node, service, hints, out),
    }
}

/// `XCL_NETWORK=0` for the whole process: the system's own network functions refuse as the
/// title's imports do (see the module's comment). Call once, before the title runs.
pub fn install_system_hooks() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        let mut unused = O_UNUSED.iter();
        let mut spare = || unused.next().expect("enough spare trampolines");
        let hooks: [(&str, &str, usize, &AtomicUsize); 20] = [
            ("winhttp.dll", "WinHttpSendRequest", send_request as usize, spare()),
            ("winhttp.dll", "WinHttpConnect", null_handle_winhttp as usize, spare()),
            ("wininet.dll", "InternetConnectA", null_handle_inet8 as usize, spare()),
            ("wininet.dll", "InternetConnectW", null_handle_inet8 as usize, spare()),
            ("wininet.dll", "InternetOpenUrlA", null_handle_inet6 as usize, spare()),
            ("wininet.dll", "InternetOpenUrlW", null_handle_inet6 as usize, spare()),
            ("wininet.dll", "HttpSendRequestA", false_inet5 as usize, spare()),
            ("wininet.dll", "HttpSendRequestW", false_inet5 as usize, spare()),
            ("wininet.dll", "HttpSendRequestExA", false_inet5 as usize, spare()),
            ("wininet.dll", "HttpSendRequestExW", false_inet5 as usize, spare()),
            ("ws2_32.dll", "connect", connect as usize, &O_CONNECT),
            ("ws2_32.dll", "WSAConnect", wsa_connect as usize, spare()),
            ("ws2_32.dll", "sendto", sendto as usize, &O_SENDTO),
            ("ws2_32.dll", "WSAIoctl", wsai_ioctl as usize, &O_WSAIOCTL),
            ("ws2_32.dll", "WSASendTo", wsa_send_to as usize, &O_WSA_SEND_TO),
            ("ws2_32.dll", "WSASendMsg", wsa_send_msg as usize, &O_WSA_SEND_MSG),
            ("ws2_32.dll", "gethostbyname", gethostbyname as usize, spare()),
            ("ws2_32.dll", "getaddrinfo", getaddrinfo as usize, &O_GETADDRINFO),
            ("ws2_32.dll", "GetAddrInfoW", getaddrinfo_w as usize, &O_GETADDRINFO_W),
            ("ws2_32.dll", "GetAddrInfoExW", getaddrinfo_ex as usize, spare()),
        ];
        let mut failed = Vec::new();
        for (dll, name, detour, orig) in hooks {
            if let Err(e) = crate::hooks::hook(dll, name, detour, orig) {
                failed.push(e);
            }
        }
        if let Err(e) = crate::hooks::hook("ws2_32.dll", "WSAConnectByList", wsa_connect_by_list as usize, &O_WSA_CONNECT_BY_LIST) {
            failed.push(e);
        }
        if failed.is_empty() {
            crate::xlog_info!("XCL_NETWORK=0: the system's WinHTTP, WinINet and Winsock refuse the network for the whole process (loopback and local names excepted)");
        } else {
            crate::xlog_warn!("XCL_NETWORK=0: not every system network function could be hooked – {}", failed.join("; "));
        }
    });
}

unsafe extern "system" fn null_handle_winhttp(_session: *mut c_void, _server: *const u16, _port: u16, _reserved: u32) -> *mut c_void {
    note("WinHttpConnect");
    SetLastError(ERROR_WINHTTP_NAME_NOT_RESOLVED);
    std::ptr::null_mut()
}

/// InternetConnectA/W (8 arguments): no connection (ERROR_INTERNET_NAME_NOT_RESOLVED – the
/// same number as WinHTTP's)
unsafe extern "system" fn null_handle_inet8(_h: *mut c_void, _server: *const c_void, _port: u16, _user: *const c_void, _pass: *const c_void, _service: u32, _flags: u32, _ctx: usize) -> *mut c_void {
    note("InternetConnect");
    SetLastError(ERROR_WINHTTP_NAME_NOT_RESOLVED);
    std::ptr::null_mut()
}

/// InternetOpenUrlA/W (6 arguments)
unsafe extern "system" fn null_handle_inet6(_h: *mut c_void, _url: *const c_void, _headers: *const c_void, _hlen: u32, _flags: u32, _ctx: usize) -> *mut c_void {
    note("InternetOpenUrl");
    SetLastError(ERROR_WINHTTP_NAME_NOT_RESOLVED);
    std::ptr::null_mut()
}

/// HttpSendRequestA/W and HttpSendRequestExA/W (5 arguments each): FALSE
unsafe extern "system" fn false_inet5(_req: *mut c_void, _a: *const c_void, _b: usize, _c: *const c_void, _d: usize) -> i32 {
    note("HttpSendRequest");
    SetLastError(ERROR_WINHTTP_NAME_NOT_RESOLVED);
    0
}

unsafe extern "system" fn send_request(_req: *mut c_void, _headers: *const u16, _hlen: u32, _opt: *const c_void, _olen: u32, _total: u32, _ctx: usize) -> i32 {
    note("WinHttpSendRequest");
    SetLastError(ERROR_WINHTTP_NAME_NOT_RESOLVED);
    0
}

unsafe extern "system" fn connect(s: usize, name: *const u8, len: i32) -> i32 {
    if loopback(name, len) {
        return orig_connect(s, name, len);
    }
    unreachable_net("connect")
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn wsai_ioctl(
    s: usize,
    code: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
    returned: *mut u32,
    overlapped: *mut c_void,
    completion: *const c_void,
) -> i32 {
    let result = orig_wsai_ioctl(s, code, in_buf, in_len, out_buf, out_len, returned, overlapped, completion);
    if result == 0
        && code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && in_len >= WSAID_CONNECTEX.len() as u32
        && out_len >= std::mem::size_of::<usize>() as u32
        && !in_buf.is_null()
        && !out_buf.is_null()
        && std::slice::from_raw_parts(in_buf as *const u8, WSAID_CONNECTEX.len()) == WSAID_CONNECTEX
    {
        let connect_ex = *(out_buf as *const usize);
        if connect_ex != 0 {
            O_CONNECT_EX.store(connect_ex, Ordering::Release);
            *(out_buf as *mut usize) = connect_ex_detour as usize;
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn connect_ex_detour(
    s: usize,
    name: *const u8,
    len: i32,
    send_buf: *const c_void,
    send_len: u32,
    bytes_sent: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    if !loopback(name, len) {
        note("ConnectEx");
        WSASetLastError(WSAENETUNREACH);
        return 0;
    }
    match O_CONNECT_EX.load(Ordering::Acquire) {
        0 => {
            WSASetLastError(WSAENETUNREACH);
            0
        }
        f => std::mem::transmute::<
            usize,
            unsafe extern "system" fn(usize, *const u8, i32, *const c_void, u32, *mut u32, *mut c_void) -> i32,
        >(f)(s, name, len, send_buf, send_len, bytes_sent, overlapped),
    }
}

unsafe extern "system" fn sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32 {
    if to.is_null() || loopback(to, tolen) {
        return orig_sendto(s, buf, len, flags, to, tolen);
    }
    unreachable_net("sendto")
}

unsafe extern "system" fn wsa_connect(s: usize, name: *const u8, len: i32, _a: *const c_void, _b: *mut c_void, _c: *const c_void, _d: *const c_void) -> i32 {
    connect(s, name, len)
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn wsa_send_to(s: usize, bufs: *const c_void, n: u32, sent: *mut u32, flags: u32, to: *const u8, tolen: i32, ov: *mut c_void, cb: *const c_void) -> i32 {
    if to.is_null() || loopback(to, tolen) {
        return orig_wsa_send_to(s, bufs, n, sent, flags, to, tolen, ov, cb);
    }
    unreachable_net("WSASendTo")
}

/// WSASendMsg has its destination in the message (WSAMSG begins with the address and its
/// length), so a datagram sent with it needs neither `sendto` nor `connect`. As in `sendto`:
/// no address (a connected socket) or loopback goes to the original.
unsafe extern "system" fn wsa_send_msg(s: usize, msg: *const c_void, flags: u32, sent: *mut u32, ov: *mut c_void, cb: *const c_void) -> i32 {
    let (to, tolen) = if msg.is_null() { (std::ptr::null(), 0) } else { ((msg as *const *const u8).read_unaligned(), (msg as *const i32).byte_add(8).read_unaligned()) };
    if to.is_null() || loopback(to, tolen) {
        return orig_wsa_send_msg(s, msg, flags, sent, ov, cb);
    }
    unreachable_net("WSASendMsg")
}

unsafe extern "system" fn gethostbyname(_name: *const u8) -> *mut c_void {
    note("gethostbyname");
    WSASetLastError(WSAHOST_NOT_FOUND);
    std::ptr::null_mut()
}

unsafe extern "system" fn getaddrinfo(node: *const c_void, _service: *const c_void, _hints: *const c_void, out: *mut *mut c_void) -> i32 {
    let name = if node.is_null() { String::new() } else { crate::util::from_ansi_ptr(node as *const u8).unwrap_or_default() };
    if local_name(&name) {
        return orig_getaddrinfo(node as *const u8, _service as *const u8, _hints, out);
    }
    note(&format!("getaddrinfo({name})"));
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
    WSAHOST_NOT_FOUND
}

unsafe extern "system" fn getaddrinfo_w(node: *const u16, _service: *const u16, _hints: *const c_void, out: *mut *mut c_void) -> i32 {
    let name = if node.is_null() { String::new() } else { crate::util::from_wide_ptr(node).unwrap_or_default() };
    if local_name(&name) {
        return orig_getaddrinfo_w(node, _service, _hints, out);
    }
    note(&format!("GetAddrInfoW({name})"));
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
    WSAHOST_NOT_FOUND
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn getaddrinfo_ex(_n: *const u16, _s: *const u16, _ns: u32, _id: *const c_void, _hints: *const c_void, out: *mut *mut c_void, _t: *const c_void, _ov: *mut c_void, _cb: *const c_void, _h: *mut c_void) -> i32 {
    note("GetAddrInfoExW");
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
    WSAHOST_NOT_FOUND
}

#[link(name = "ws2_32", kind = "raw-dylib")]
extern "system" {
    #[link_name = "WSAConnectByList"]
    fn real_wsa_connect_by_list(s: usize, list: *const u8, local_len: *mut u32, local: *mut u8, remote_len: *mut u32, remote: *mut u8, timeout: *const c_void, reserved: *mut c_void) -> i32;
}

static O_WSA_CONNECT_BY_LIST: AtomicUsize = AtomicUsize::new(0);

/// SOCKET_ADDRESS_LIST on x64: an INT count, then (at 8) SOCKET_ADDRESS entries of
/// { LPSOCKADDR, INT } padded to 16 bytes
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketAddress {
    addr: *const u8,
    len: i32,
}

/// The loopback entries of a SOCKET_ADDRESS_LIST, and how many entries it has.
unsafe fn loopback_entries(list: *const u8) -> (Vec<SocketAddress>, usize) {
    if list.is_null() {
        return (Vec::new(), 0);
    }
    let n = (list as *const i32).read_unaligned().max(0) as usize;
    let first = list.add(8) as *const SocketAddress;
    let keep = (0..n).map(|k| first.add(k).read_unaligned()).filter(|a| loopback(a.addr, a.len)).collect();
    (keep, n)
}

/// WSAConnectByList connects to the first address of a list that answers, without calling the
/// hooked connect – so it went to the network with XCL_NETWORK=0. Loopback entries still go
/// through (in their order); a list with none fails as connect does.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn wsa_connect_by_list(s: usize, list: *const u8, local_len: *mut u32, local: *mut u8, remote_len: *mut u32, remote: *mut u8, timeout: *const c_void, reserved: *mut c_void) -> i32 {
    let (keep, n) = loopback_entries(list);
    if keep.is_empty() {
        unreachable_net("WSAConnectByList");
        return 0; // FALSE
    }
    // only loopback: the title's own list; otherwise a copy of the list with the loopback
    // entries (count, then 16-byte entries from offset 8)
    let mut own: Vec<u64> = Vec::new();
    let list = if keep.len() == n {
        list
    } else {
        own.push(keep.len() as u64);
        for e in &keep {
            own.extend_from_slice(&[e.addr as u64, e.len as u32 as u64]);
        }
        own.as_ptr() as *const u8
    };
    match O_WSA_CONNECT_BY_LIST.load(Ordering::Acquire) {
        0 => real_wsa_connect_by_list(s, list, local_len, local, remote_len, remote, timeout, reserved),
        f => std::mem::transmute::<usize, unsafe extern "system" fn(usize, *const u8, *mut u32, *mut u8, *mut u32, *mut u8, *const c_void, *mut c_void) -> i32>(f)(
            s, list, local_len, local, remote_len, remote, timeout, reserved,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_goes_through() {
        let v4 = |a: [u8; 4]| [2, 0, 0, 80, a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0];
        let mut v6 = [0u8; 28];
        v6[0] = 23;
        v6[23] = 1;
        unsafe {
            assert!(loopback(v4([127, 0, 0, 1]).as_ptr(), 16));
            assert!(!loopback(v4([8, 8, 8, 8]).as_ptr(), 16));
            assert!(loopback(v6.as_ptr(), 28));
            v6[8] = 0x20;
            assert!(!loopback(v6.as_ptr(), 28));
            let mapped = |a: [u8; 4]| {
                let mut m = [0u8; 28];
                m[0] = 23;
                m[18..24].copy_from_slice(&[0xff, 0xff, a[0], a[1], a[2], a[3]]);
                m
            };
            assert!(loopback(mapped([127, 0, 0, 1]).as_ptr(), 28));
            assert!(!loopback(mapped([8, 8, 8, 8]).as_ptr(), 28));
            assert_eq!(connect(usize::MAX, v4([8, 8, 8, 8]).as_ptr(), 16), -1);
            assert_eq!(send_request(std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null(), 0, 0, 0), 0);
        }
    }

    /// WSAConnectByList skipped every hook and connected out (a live connect to 192.0.2.1:80
    /// ran until WSAETIMEDOUT). Now a list without loopback fails with WSAENETUNREACH, through
    /// the title's import and through the system's own export, and loopback entries still go on.
    #[test]
    fn wsa_connect_by_list_refuses_all_but_loopback() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        #[link(name = "ws2_32", kind = "raw-dylib")]
        extern "system" {
            fn WSAGetLastError() -> i32;
        }
        let v4 = |a: [u8; 4]| [2u8, 0, 0, 80, a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0];
        let (lo, out) = (v4([127, 0, 0, 1]), v4([192, 0, 2, 1]));
        let list = |addrs: &[&[u8; 16]]| -> Vec<u64> {
            let mut l = vec![addrs.len() as u64];
            for a in addrs {
                l.extend_from_slice(&[a.as_ptr() as u64, 16]);
            }
            l
        };
        let (none, mixed, only) = (list(&[&out]), list(&[&out, &lo]), list(&[&lo]));
        unsafe {
            let (keep, n) = loopback_entries(mixed.as_ptr() as *const u8);
            assert_eq!((keep.len(), n), (1, 2));
            assert_eq!(keep[0].addr, lo.as_ptr());
            assert_eq!(loopback_entries(std::ptr::null()).1, 0);

            type ByList = unsafe extern "system" fn(usize, *const u8, *mut u32, *mut u8, *mut u32, *mut u8, *const c_void, *mut c_void) -> i32;
            let call = |f: ByList, l: &[u64]| -> i32 {
                WSASetLastError(0);
                assert_eq!(f(usize::MAX, l.as_ptr() as *const u8, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()), 0);
                WSAGetLastError()
            };
            install_system_hooks();
            let Some(raw) = GetProcAddress(LoadLibraryW(crate::util::wide("ws2_32.dll").as_ptr()), b"WSAConnectByList\0".as_ptr()) else {
                // Wine/Proton ws2_32.dll does not export WSAConnectByList: still verify our detour refuses non-loopback.
                assert_eq!(call(wsa_connect_by_list as ByList, &none), WSAENETUNREACH, "a list without loopback");
                return;
            };
            let system: ByList = std::mem::transmute(raw);
            for f in [wsa_connect_by_list as ByList, system] {
                assert_eq!(call(f, &none), WSAENETUNREACH, "a list without loopback");
                // loopback reaches the original, which fails on the invalid socket instead
                assert_ne!(call(f, &mixed), WSAENETUNREACH, "the loopback entry of a mixed list");
                assert_ne!(call(f, &only), WSAENETUNREACH, "a loopback list");
            }
        }
    }

    /// With the system hooks, the system's own functions refuse – found the way a crash
    /// reporter can find them, through GetProcAddress, not the title's imports (#305) – and
    /// what may go through still reaches the original.
    #[test]
    fn the_systems_own_network_functions_refuse() {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        #[link(name = "ws2_32", kind = "raw-dylib")]
        unsafe extern "system" {
            fn WSAStartup(version: u16, data: *mut u8) -> i32;
            fn WSAGetLastError() -> i32;
            fn socket(af: i32, ty: i32, protocol: i32) -> usize;
            fn closesocket(s: usize) -> i32;
        }
        install_system_hooks();
        unsafe {
            let f = |dll: &str, name: &[u8]| GetProcAddress(LoadLibraryW(crate::util::wide(dll).as_ptr()), name.as_ptr()).expect("export") as usize;
            let send: unsafe extern "system" fn(*mut c_void, *const u16, u32, *const c_void, u32, u32, usize) -> i32 = std::mem::transmute(f("winhttp.dll", b"WinHttpSendRequest\0"));
            SetLastError(0);
            assert_eq!(send(1 as *mut c_void, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0), 0);
            assert_eq!(GetLastError(), ERROR_WINHTTP_NAME_NOT_RESOLVED);
            let open_url: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32, u32, usize) -> *mut c_void = std::mem::transmute(f("wininet.dll", b"InternetOpenUrlW\0"));
            assert!(open_url(1 as *mut c_void, crate::util::wide("https://example.com/").as_ptr(), std::ptr::null(), 0, 0, 0).is_null());
            // a name lookup is refused (11001) – a lookup of localhost reaches the original,
            // which answers something else (an address, or 10093 without WSAStartup)
            let gai: unsafe extern "system" fn(*const u8, *const u8, *const c_void, *mut *mut c_void) -> i32 = std::mem::transmute(f("ws2_32.dll", b"getaddrinfo\0"));
            let mut out = std::ptr::null_mut();
            assert_eq!(gai(b"example.com\0".as_ptr(), std::ptr::null(), std::ptr::null(), &mut out), WSAHOST_NOT_FOUND);
            assert!(out.is_null());
            assert_ne!(gai(b"localhost\0".as_ptr(), std::ptr::null(), std::ptr::null(), &mut out), WSAHOST_NOT_FOUND);

            // ConnectEx is not an export: WSAIoctl hands the caller a function pointer.
            // The system hook must replace that pointer, otherwise this path bypasses all
            // network refusals (issue #444).
            let mut wsa = [0u8; 512];
            assert_eq!(WSAStartup(0x0202, wsa.as_mut_ptr()), 0);
            let ioctl: unsafe extern "system" fn(usize, u32, *const c_void, u32, *mut c_void, u32, *mut u32, *mut c_void, *const c_void) -> i32 =
                std::mem::transmute(f("ws2_32.dll", b"WSAIoctl\0"));
            let s = socket(2, 1, 6);
            assert_ne!(s, usize::MAX);
            let mut connect_ex = 0usize;
            let mut returned = 0u32;
            assert_eq!(ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_CONNECTEX.as_ptr() as *const c_void, WSAID_CONNECTEX.len() as u32, &mut connect_ex as *mut usize as *mut c_void, std::mem::size_of::<usize>() as u32, &mut returned, std::ptr::null_mut(), std::ptr::null()), 0);
            assert_eq!(connect_ex, connect_ex_detour as usize);
            let connect_ex: unsafe extern "system" fn(usize, *const u8, i32, *const c_void, u32, *mut u32, *mut c_void) -> i32 = std::mem::transmute(connect_ex);
            let mut external = [0u8; 16];
            external[0] = 2;
            external[4..8].copy_from_slice(&[8, 8, 8, 8]);
            assert_eq!(connect_ex(s, external.as_ptr(), 16, std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut()), 0);
            assert_eq!(WSAGetLastError(), WSAENETUNREACH);
            closesocket(s);
        }
    }

    #[test]
    fn local_name_parses_loopback_ips() {
        assert!(!local_name("127.example.com"));
        assert!(!local_name("127.0.0.1.example.com"));
        assert!(!local_name("127.999.0.1"));
        assert!(!local_name("192.0.2.1"));
        assert!(!local_name("example.invalid"));
        assert!(local_name(""));
        assert!(local_name("localhost"));
        assert!(local_name("LOCALHOST"));
        assert!(local_name("127.0.0.1"));
        assert!(local_name("127.255.255.254"));
        assert!(local_name("::1"));
        assert!(local_name("0:0:0:0:0:0:0:1"));
    }

    /// WSASendMsg, found as the functions above are: a datagram to another host is refused.
    /// No socket is needed to see who answers – the hook refuses before it looks at the socket
    /// (10051), the system's own function says something else (10038 not a socket, or 10093
    /// without WSAStartup), which is also what loopback gets, sent on to it.
    #[test]
    fn the_systems_wsasendmsg_refuses() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        #[link(name = "ws2_32", kind = "raw-dylib")]
        extern "system" {
            fn WSAGetLastError() -> i32;
        }
        install_system_hooks();
        unsafe {
            let f = GetProcAddress(LoadLibraryW(crate::util::wide("ws2_32.dll").as_ptr()), b"WSASendMsg\0".as_ptr()).expect("export") as usize;
            let send_msg: unsafe extern "system" fn(usize, *const c_void, u32, *mut u32, *mut c_void, *const c_void) -> i32 = std::mem::transmute(f);
            let mut to = [2u8, 0, 0, 53, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut byte = [0u8];
            // WSABUF { len, buf }, WSAMSG { name, namelen, lpBuffers, dwBufferCount, Control, dwFlags }
            let buf = [1usize, byte.as_mut_ptr() as usize];
            let mut sent = 0u32;
            let mut send = |to: &[u8; 16]| {
                let msg = [to.as_ptr() as usize, 16, buf.as_ptr() as usize, 1, 0, 0, 0];
                WSASetLastError(0);
                assert_eq!(send_msg(usize::MAX, msg.as_ptr() as *const c_void, 0, &mut sent, std::ptr::null_mut(), std::ptr::null()), -1);
                WSAGetLastError()
            };
            assert_eq!(send(&to), WSAENETUNREACH);
            to[4..8].copy_from_slice(&[127, 0, 0, 1]);
            assert_ne!(send(&to), WSAENETUNREACH);
        }
    }

    #[test]
    fn wsa_send_to_lets_loopback_through() {
        #[link(name = "ws2_32", kind = "raw-dylib")]
        extern "system" {
            fn WSAGetLastError() -> i32;
        }
        let v4 = |a: [u8; 4]| [2, 0, 0, 80, a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0];
        let mut sent = 0u32;
        unsafe {
            // Non-loopback destination is blocked with WSAENETUNREACH (10051).
            WSASetLastError(0);
            assert_eq!(wsa_send_to(usize::MAX, std::ptr::null(), 0, &mut sent, 0, v4([8, 8, 8, 8]).as_ptr(), 16, std::ptr::null_mut(), std::ptr::null()), -1);
            assert_eq!(WSAGetLastError(), WSAENETUNREACH);

            // Loopback destination reaches the original WSASendTo (fails with WSAENOTSOCK/WSANOTINITIALISED, not WSAENETUNREACH).
            WSASetLastError(0);
            let _ = wsa_send_to(usize::MAX, std::ptr::null(), 0, &mut sent, 0, v4([127, 0, 0, 1]).as_ptr(), 16, std::ptr::null_mut(), std::ptr::null());
            assert_ne!(WSAGetLastError(), WSAENETUNREACH);

            // Null destination (connected socket) also reaches the original WSASendTo, matching sendto.
            WSASetLastError(0);
            let _ = wsa_send_to(usize::MAX, std::ptr::null(), 0, &mut sent, 0, std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null());
            assert_ne!(WSAGetLastError(), WSAENETUNREACH);
        }
    }
}
