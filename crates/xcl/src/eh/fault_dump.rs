//! `XCL_FAULT_DUMP=1`: the memory around the pointers of an unhandled exception.
//!
//! The crash line names the registers; this shows what the title's data there looked like: for
//! each register, the faulting address and, when the faulting address is below 4 GiB, that address
//! under the upper half of each register that points at readable memory (a title that lost the
//! upper half of a pointer faults at the truncated address), 256 bytes on either side as 32-bit
//! words. Off by default; at most the first 2 faults of the process, one at a time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Bytes shown on either side of a pointer.
const AROUND: u64 = 0x100;
/// Bytes per printed line (8 words).
const LINE: u64 = 32;
/// Lines per fault, headers included.
pub const MAX_LINES: usize = 300;
/// Truncated-pointer candidates per fault.
const MAX_REBASED: usize = 4;

pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("XCL_FAULT_DUMP").is_ok_and(|v| v == "1"))
}

/// The 16-byte line holding `p` can be read.
fn line_readable(p: u64, read: &dyn Fn(u64, &mut [u8]) -> bool) -> bool {
    let mut b = [0u8; 16];
    read(p & !0xF, &mut b)
}

/// The pointers to dump, named, without repeats: registers, the faulting address, and the
/// faulting address (below 4 GiB) under the upper half of each register that is a readable pointer.
pub fn candidates(regs: &[(&str, u64)], fault: Option<u64>, read: &dyn Fn(u64, &mut [u8]) -> bool) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    let push = |out: &mut Vec<(String, u64)>, name: String, p: u64| {
        if !out.iter().any(|(_, q)| *q == p) && line_readable(p, read) {
            out.push((name, p));
        }
    };
    for (n, v) in regs {
        push(&mut out, (*n).to_string(), *v);
    }
    if let Some(f) = fault {
        push(&mut out, "fault".into(), f);
        if f >> 32 == 0 {
            let mut highs: Vec<u64> = Vec::new();
            for (n, v) in regs {
                let hi = v >> 32;
                if hi == 0 || highs.contains(&hi) || highs.len() >= MAX_REBASED || !line_readable(*v, read) {
                    continue;
                }
                highs.push(hi);
                push(&mut out, format!("fault under {n}'s upper half"), (hi << 32) | f);
            }
        }
    }
    out
}

/// The dump lines of `cands`: a header per pointer, then 32-byte lines from 256 bytes before to
/// 256 bytes after it, the line holding it marked; a line printed for an earlier pointer is not
/// printed again. At most `cap` lines.
pub fn format(cands: &[(String, u64)], read: &dyn Fn(u64, &mut [u8]) -> bool, cap: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut done: Vec<u64> = Vec::new();
    for (name, p) in cands {
        let at = p & !(LINE - 1);
        let (lo, hi) = (at.saturating_sub(AROUND), at.saturating_add(AROUND));
        if lines.len() + 1 >= cap {
            lines.push("fault dump: line limit reached".to_string());
            return lines;
        }
        lines.push(format!("fault dump: {name}={p:#x}"));
        let mut a = lo;
        while a <= hi {
            if !done.contains(&a) {
                if lines.len() + 1 >= cap {
                    lines.push("fault dump: line limit reached".to_string());
                    return lines;
                }
                done.push(a);
                let mark = if a == at { " <==" } else { "" };
                let mut b = [0u8; LINE as usize];
                if read(a, &mut b) {
                    let w: String = b.chunks(4).map(|c| format!(" {:08x}", u32::from_le_bytes([c[0], c[1], c[2], c[3]]))).collect();
                    lines.push(format!("fault dump: {a:#014x}:{w}{mark}"));
                } else {
                    lines.push(format!("fault dump: {a:#014x}: unreadable{mark}"));
                }
            }
            match a.checked_add(LINE) {
                Some(n) => a = n,
                None => break,
            }
        }
    }
    lines
}

/// The whole report for one fault (empty when the switch is off or after the first 2 faults).
pub fn report(on: bool, count: &AtomicUsize, regs: &[(&str, u64)], fault: Option<u64>, read: &dyn Fn(u64, &mut [u8]) -> bool) -> Vec<String> {
    if !on || count.fetch_add(1, Ordering::Relaxed) >= 2 {
        return Vec::new();
    }
    format(&candidates(regs, fault, read), read, MAX_LINES)
}

/// Reads the current process only where `gpu::shader::readable` says the memory is committed
/// and readable: a fault inside the unhandled-exception filter would end the report.
fn read_here(a: u64, buf: &mut [u8]) -> bool {
    let Ok(p) = usize::try_from(a) else { return false };
    if p < 0x10000 || !crate::gpu::shader::readable(p, buf.len()) {
        return false;
    }
    unsafe { std::ptr::copy_nonoverlapping(p as *const u8, buf.as_mut_ptr(), buf.len()) };
    true
}

/// Logs the dump for a title's unhandled exception, when `XCL_FAULT_DUMP=1`.
pub fn log(regs: &[(&str, u64)], fault: Option<u64>) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static LOCK: Mutex<()> = Mutex::new(());
    if !enabled() {
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for l in report(true, &COUNT, regs, fault, &read_here) {
        crate::xlog_error!("{l}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory [base, base + len) is readable and holds its own address's low bytes
    fn mem(ranges: &'static [(u64, u64)]) -> impl Fn(u64, &mut [u8]) -> bool {
        move |a, buf| {
            let end = a + buf.len() as u64;
            if !ranges.iter().any(|&(b, l)| a >= b && end <= b + l) {
                return false;
            }
            for (i, x) in buf.iter_mut().enumerate() {
                *x = (a + i as u64) as u8;
            }
            true
        }
    }

    #[test]
    fn candidates_take_readable_registers_and_the_fault_once() {
        let r = mem(&[(0x1000, 0x1000)]);
        let regs = [("rax", 0x1010), ("rbx", 0x9000), ("rcx", 0x1010), ("rdx", 0x1800)];
        let c = candidates(&regs, Some(0x1800), &r);
        assert_eq!(c, vec![("rax".to_string(), 0x1010), ("rdx".to_string(), 0x1800)]);
        let c = candidates(&regs, Some(0x1F00), &r);
        assert_eq!(c.last().unwrap(), &("fault".to_string(), 0x1F00));
    }

    #[test]
    fn candidates_rebase_a_truncated_fault_under_pointer_upper_halves() {
        let r = mem(&[(0x7_0000_1000, 0x1000), (0x8_0000_0000, 0x100), (0x9_0000_2000, 0x100)]);
        let regs = [("rax", 0x7_0000_1010), ("rbx", 0x7_0000_1020), ("rcx", 0x8_0000_0000), ("rdx", 0x9_0000_0000)];
        let c = candidates(&regs, Some(0x2000), &r);
        let names: Vec<&str> = c.iter().map(|(n, _)| n.as_str()).collect();
        // rax and rbx share an upper half, rdx is not readable, 9<<32|0x2000 is
        assert_eq!(names, ["rax", "rbx", "rcx"]);
        let c = candidates(&regs, Some(0x1080), &r);
        assert_eq!(c[3], ("fault under rax's upper half".to_string(), 0x7_0000_1080));
        assert_eq!(c.len(), 4);
        // no rebasing above 4 GiB
        let c = candidates(&regs, Some(0x1_0000_1080), &r);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn candidates_rebase_at_most_a_few() {
        static R: [(u64, u64); 6] = [(0x1_0000_0000, 0x2000), (0x2_0000_0000, 0x2000), (0x3_0000_0000, 0x2000), (0x4_0000_0000, 0x2000), (0x5_0000_0000, 0x2000), (0x6_0000_0000, 0x2000)];
        let r = mem(&R);
        let regs: Vec<(&str, u64)> = ["a", "b", "c", "d", "e", "f"].iter().zip(1u64..).map(|(n, i)| (*n, i << 32)).collect();
        let c = candidates(&regs, Some(0x1000), &r);
        assert_eq!(c.iter().filter(|(n, _)| n.starts_with("fault under")).count(), MAX_REBASED);
    }

    #[test]
    fn format_marks_the_line_and_prints_words() {
        let r = mem(&[(0x1000, 0x1000)]);
        let l = format(&[("rax".into(), 0x1234)], &r, MAX_LINES);
        assert_eq!(l[0], "fault dump: rax=0x1234");
        assert_eq!(l.len(), 1 + 17);
        assert_eq!(l[1], "fault dump: 0x000000001120: 23222120 27262524 2b2a2928 2f2e2d2c 33323130 37363534 3b3a3938 3f3e3d3c");
        let marked: Vec<&String> = l.iter().filter(|s| s.ends_with(" <==")).collect();
        assert_eq!(marked.len(), 1);
        assert!(marked[0].starts_with("fault dump: 0x000000001220: 23222120"));
    }

    #[test]
    fn format_says_unreadable_and_skips_lines_already_shown() {
        let r = mem(&[(0x1000, 0x100)]);
        let l = format(&[("rax".into(), 0x1000), ("rbx".into(), 0x1040)], &r, MAX_LINES);
        assert_eq!(l[1], "fault dump: 0x000000000f00: unreadable");
        assert!(l[9].starts_with("fault dump: 0x000000001000: 03020100") && l[9].ends_with(" <=="));
        // rbx's window adds only the two lines past rax's
        assert_eq!(l.len(), 1 + 17 + 1 + 2);
        assert_eq!(l[18], "fault dump: rbx=0x1040");
    }

    #[test]
    fn format_stops_at_the_cap() {
        let r = mem(&[(0, 0x10_0000)]);
        let c: Vec<(String, u64)> = (0..40u64).map(|i| (format!("r{i}"), 0x1000 + i * 0x1000)).collect();
        let l = format(&c, &r, MAX_LINES);
        assert_eq!(l.len(), MAX_LINES);
        assert_eq!(l.last().unwrap(), "fault dump: line limit reached");
    }

    #[test]
    fn report_is_empty_when_off_and_after_two_faults() {
        let r = mem(&[(0x1000, 0x1000)]);
        let regs = [("rax", 0x1100)];
        let n = AtomicUsize::new(0);
        assert!(report(false, &n, &regs, None, &r).is_empty());
        assert!(!report(true, &n, &regs, None, &r).is_empty());
        assert!(!report(true, &n, &regs, None, &r).is_empty());
        assert!(report(true, &n, &regs, None, &r).is_empty());
    }
}
