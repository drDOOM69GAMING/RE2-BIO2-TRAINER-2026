use std::sync::mpsc::Sender;

use crate::process::{self, ProcessHandle};

pub enum ScanEvent {
    Initial(Vec<(usize, f32)>),
    Sub(Vec<(usize, f32)>),
    Pointer(Vec<PointerCandidate>),
}

#[derive(Clone, Debug)]
pub struct PointerCandidate {
    pub module: String,
    pub rel_offset: usize,
    pub delta: isize,
}

#[derive(Clone, Copy, Debug)]
pub enum ScanPass {
    Decreased,
    Increased,
    Changed,
    Unchanged,
}

const CHUNK: usize = 4 * 1024 * 1024;

fn is_exact(buf: &[u8], i: usize, bits: u32) -> bool {
    i + 3 < buf.len() && u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) == bits
}

pub fn run_initial(h: ProcessHandle, value: f32, tx: Sender<ScanEvent>) {
    let bits = value.to_bits();
    let mut out = Vec::new();
    unsafe {
        let regions = process::readable_regions(h);
        for (addr, len) in &regions {
            let mut off = 0usize;
            while off < *len {
                let clen = (*len - off).min(CHUNK);
                if let Some(buf) = process::read_bytes(h, addr + off, clen) {
                    for i in (0..clen.saturating_sub(3)).step_by(4) {
                        if is_exact(&buf, i, bits) {
                            out.push((addr + off + i, f32::from_bits(bits)));
                        }
                    }
                }
                off += clen;
            }
        }
    }
    let _ = tx.send(ScanEvent::Initial(out));
}

pub fn run_pair_initial(h: ProcessHandle, lo: f32, hi: f32) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    unsafe {
        let regions = process::readable_regions(h);
        for (addr, len) in &regions {
            let mut off = 0usize;
            while off < *len {
                let clen = (*len - off).min(CHUNK);
                if let Some(buf) = process::read_bytes(h, addr + off, clen) {
                    for i in (0..clen.saturating_sub(7)).step_by(4) {
                        let a = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                        let b = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
                        let fa = f32::from_bits(a);
                        if a == b && fa >= lo && fa <= hi {
                            out.push((addr + off + i, a));
                        }
                    }
                }
                off += clen;
            }
        }
    }
    out
}

pub fn run_pair_next(h: ProcessHandle, prev: &[(usize, u32)], equal: bool) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    for (addr, _) in prev {
        let Some(bytes) = (unsafe { process::read_bytes(h, *addr, 8) }) else {
            continue;
        };
        let a = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let b = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if (a == b) == equal {
            out.push((*addr, a));
        }
    }
    out
}

pub fn run_sub(h: ProcessHandle, prev: Vec<(usize, f32)>, pass: ScanPass, tx: Sender<ScanEvent>) {
    let mut out = Vec::new();
    for (addr, before) in &prev {
        unsafe {
            if let Some(cur) = process::read_memory::<f32>(h, *addr) {
                let keep = match pass {
                    ScanPass::Decreased => cur < *before,
                    ScanPass::Increased => cur > *before,
                    ScanPass::Changed => cur != *before,
                    ScanPass::Unchanged => cur == *before,
                };
                if keep {
                    out.push((*addr, cur));
                }
            }
        }
    }
    let _ = tx.send(ScanEvent::Sub(out));
}

pub fn run_pointer(
    h: ProcessHandle,
    pid: u32,
    target: usize,
    module: String,
    tx: Sender<ScanEvent>,
) {
    let module_name = module.trim_end_matches('\0').to_lowercase();
    let mut out = Vec::new();
    unsafe {
        for (name, base, size) in process::modules(pid) {
            let name = name.to_lowercase();
            let matches = name == module_name || name.starts_with("re_chunk");
            if !matches {
                continue;
            }
            let mut addr = base;
            let end = base.saturating_add(size);
            while addr < end {
                let len = (end - addr).min(CHUNK);
                if let Some(buf) = process::read_bytes(h, addr, len) {
                    for i in (0..len.saturating_sub(7)).step_by(8) {
                        let raw = u64::from_le_bytes([
                            buf[i],
                            buf[i + 1],
                            buf[i + 2],
                            buf[i + 3],
                            buf[i + 4],
                            buf[i + 5],
                            buf[i + 6],
                            buf[i + 7],
                        ]);
                        if raw < 0x10000 || raw > 0x0000FF_FFFF_FFFF_FFFF {
                            continue;
                        }
                        let x = process::read_memory::<usize>(h, raw as usize);
                        let Some(x) = x else { continue };
                        let d = target as i64 - x as i64;
                        if d >= 0 && d <= 0x1000 {
                            out.push(PointerCandidate {
                                module: name.clone(),
                                rel_offset: addr + i - base,
                                delta: d as isize,
                            });
                            if out.len() >= 2000 {
                                break;
                            }
                        }
                    }
                }
                addr += len;
            }
            if out.len() >= 2000 {
                break;
            }
        }
    }
    out.sort_by_key(|c| (c.delta.abs(), c.rel_offset));
    let _ = tx.send(ScanEvent::Pointer(out));
}