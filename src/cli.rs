use std::fs;
use std::sync::mpsc::channel;

use crate::process::{self, ProcessHandle};
use crate::scanner::{self, ScanEvent};

const GAME_EXE: &str = "re2.exe";
const DEFAULT_FILE: &str = "candidates.txt";

fn parse_float(s: &str) -> Result<f32, String> {
    s.parse().map_err(|_| format!("bad float: {s}"))
}

fn parse_addr(s: &str) -> Result<usize, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    usize::from_str_radix(t, 16).map_err(|_| format!("bad hex address: {s}"))
}

fn parse_off(s: &str) -> Option<isize> {
    let t = s.trim();
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits = rest.trim_start_matches("0x").trim_start_matches("0X");
    let v = isize::from_str_radix(digits, 16).ok()?;
    Some(if neg { -v } else { v })
}

fn parse_offsets(s: &str) -> Result<Vec<isize>, String> {
    s.split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|p| parse_off(p).ok_or_else(|| format!("bad offset: {p}")))
        .collect()
}

fn attach() -> Result<(u32, ProcessHandle, String, usize), String> {
    let pid =
        process::find_process(GAME_EXE).ok_or_else(|| "re2.exe is not running".to_string())?;
    let h = process::open_process(pid)
        .ok_or_else(|| "could not open process - run from an elevated terminal".to_string())?;
    let mods = process::modules(pid);
    let chunk = mods
        .iter()
        .find(|(n, _, _)| n.to_lowercase().starts_with("re_chunk"))
        .or_else(|| mods.first())
        .map(|(n, b, _)| (n.clone(), *b))
        .ok_or_else(|| "no modules enumerated".to_string())?;
    Ok((pid, h, chunk.0, chunk.1))
}

fn load_candidates(path: &str) -> Result<Vec<(usize, u32)>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(a), Some(b)) = (parts.next(), parts.next()) {
            out.push((parse_addr(a)?, b.parse().map_err(|_| format!("bad bits: {b}"))?));
        }
    }
    Ok(out)
}

fn save_candidates(path: &str, list: &[(usize, u32)]) -> Result<(), String> {
    let mut text = String::new();
    for (addr, bits) in list {
        text.push_str(&format!("{:X} {}\n", addr, bits));
    }
    fs::write(path, text).map_err(|e| e.to_string())
}

pub fn run(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("usage: re2-trainer --cli <probe|scan|next|value|write|ptr|apply> ...");
        return 1;
    };
    let result = run_cmd(cmd.as_str(), &args[1..]);
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_cmd(cmd: &str, a: &[String]) -> Result<(), String> {
    match cmd {
        "probe" => {
            let (pid, h, name, base) = attach()?;
            let regs = unsafe { process::readable_regions(h) };
            let total: usize = regs.iter().map(|(_, l)| *l).sum();
            let regions = regs.len();
            println!("pid={pid} handle={h} module={name} base=0x{base:X} readable_regions={regions} readable_bytes=0x{total:X}");
            Ok(())
        }
        "scan" => {
            let val = a.first().ok_or("missing value")?;
            let val = parse_float(val)?;
            let file = a.get(1).map(String::as_str).unwrap_or(DEFAULT_FILE);
            let (pid, h, _, _) = attach()?;
            let (tx, rx) = channel();
            let hh = h;
            std::thread::spawn(move || scanner::run_initial(hh, val, tx));
            let list = match rx.recv().map_err(|_| "scan thread failed")? {
                ScanEvent::Initial(list) => list,
                _ => return Err("unexpected scan result".to_string()),
            };
            let as_bits: Vec<(usize, u32)> = list
                .iter()
                .map(|(addr, v)| (*addr, v.to_bits()))
                .collect();
            save_candidates(file, &as_bits)?;
            println!("count={} file={file}", as_bits.len());
            for (addr, v) in as_bits.iter().take(30) {
                println!("0x{addr:X} {}", f32::from_bits(*v));
            }
            let _ = pid;
            Ok(())
        }
        "pair" => {
            let lo = a.first().ok_or("missing lo")?;
            let hi = a.get(1).ok_or("missing hi")?;
            let file = a.get(2).map(String::as_str).unwrap_or(DEFAULT_FILE);
            let lo = parse_float(lo)?;
            let hi = parse_float(hi)?;
            let (_, h, _, _) = attach()?;
            let list = scanner::run_pair_initial(h, lo, hi);
            save_candidates(file, &list)?;
            println!("pair-equality count={} file={file} range=[{lo},{hi}]", list.len());
            for (addr, v) in list.iter().take(30) {
                println!("0x{addr:X} {} == {}", f32::from_bits(*v), f32::from_bits(*v));
            }
            Ok(())
        }
        "pnext" => {
            let mode = a.first().ok_or("missing mode (changed|unchanged)")?;
            let file = a.get(1).map(String::as_str).unwrap_or(DEFAULT_FILE);
            let (_, h, _, _) = attach()?;
            let prev = load_candidates(file)?;
            let equal = match mode.as_str() {
                "changed" => false,
                "unchanged" => true,
                _ => return Err("mode must be changed|unchanged".to_string()),
            };
            let kept = scanner::run_pair_next(h, &prev, equal);
            save_candidates(file, &kept)?;
            println!("count={} file={file}", kept.len());
            for (addr, v) in kept.iter().take(30) {
                println!("0x{addr:X} {}", f32::from_bits(*v));
            }
            Ok(())
        }
        "writeb" => {
            let addr = a.first().ok_or("missing address")?;
            let val = a.get(1).ok_or("missing byte value")?;
            let addr = parse_addr(addr)?;
            let val: u8 = val.parse().map_err(|_| "bad byte")?;
            let (_, h, _, _) = attach()?;
            let buf = unsafe { process::read_bytes(h, addr, 1) }
                .ok_or_else(|| "read failed".to_string())?;
            if unsafe { process::write_memory(h, addr, &[val]) } {
                println!("0x{addr:X} <= 0x{val:X} (was 0x{:02X})", buf[0]);
                Ok(())
            } else {
                Err("write failed".to_string())
            }
        }
        "next" => {
            let pass = a.first().ok_or("missing pass")?;
            let file = a.get(1).map(String::as_str).unwrap_or(DEFAULT_FILE);
            let (_, h, _, _) = attach()?;
            let mut kept = Vec::new();
            for (addr, bits) in load_candidates(file)? {
                let before = f32::from_bits(bits);
                if let Some(cur) = unsafe { process::read_memory::<f32>(h, addr) } {
                    let keep = match pass.as_str() {
                        "decreased" => cur < before,
                        "increased" => cur > before,
                        "changed" => cur != before,
                        "unchanged" => cur == before,
                        _ => return Err(format!("bad pass: {pass}")),
                    };
                    if keep {
                        kept.push((addr, cur.to_bits()));
                    }
                }
            }
            save_candidates(file, &kept)?;
            println!("count={} file={file}", kept.len());
            for (addr, v) in kept.iter().take(30) {
                println!("0x{addr:X} {}", f32::from_bits(*v));
            }
            Ok(())
        }
        "value" => {
            let addr = a.first().ok_or("missing address")?;
            let addr = parse_addr(addr)?;
            let (_, h, _, _) = attach()?;
            if let Some(v) = unsafe { process::read_memory::<f32>(h, addr) } {
                println!("0x{addr:X} = {v}");
                Ok(())
            } else {
                Err("read failed".to_string())
            }
        }
        "write" => {
            let addr = a.first().ok_or("missing address")?;
            let val = a.get(1).ok_or("missing value")?;
            let addr = parse_addr(addr)?;
            let val = parse_float(val)?;
            let (_, h, _, _) = attach()?;
            if unsafe { process::write_memory(h, addr, &val) } {
                println!("0x{addr:X} <= {val}");
                Ok(())
            } else {
                Err("write failed".to_string())
            }
        }
        "ptr" => {
            let addr = a.first().ok_or("missing address")?;
            let limit = a.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(30);
            let addr = parse_addr(addr)?;
            let (pid, h, name, _) = attach()?;
            let (tx, rx) = channel();
            let hh = h;
            let module = name.clone();
            std::thread::spawn(move || scanner::run_pointer(hh, pid, addr, module, tx));
            let list = match rx.recv().map_err(|_| "ptr thread failed")? {
                ScanEvent::Pointer(list) => list,
                _ => return Err("unexpected ptr result".to_string()),
            };
            println!("ptr candidates={} target=0x{addr:X} module={name}", list.len());
            for c in list.iter().take(limit) {
                println!("{}+{:X} (+{:X})", c.module, c.rel_offset, c.delta);
            }
            Ok(())
        }
        "apply" => {
            let offs = a.first().ok_or("missing offsets")?;
            let offs = parse_offsets(offs)?;
            let (_, h, _, base) = attach()?;
            let addr = unsafe { process::resolve_chain(h, base, &offs) }
                .ok_or("chain resolve failed")?;
            let cur = unsafe { process::read_memory::<f32>(h, addr) };
            let mut target = 1000.0f32;
            if let Some(v) = cur {
                if v != target {
                    let _ = unsafe { process::write_memory(h, addr, &target) };
                }
            } else {
                return Err("read failed at resolved address".to_string());
            }
            println!(
                "addr=0x{addr:X} before={} after={target} offsets={offs:?}",
                cur.unwrap_or(0.0)
            );
            let _ = &mut target;
            Ok(())
        }
        "dump" => {
            let addr = a.first().ok_or("missing addr")?;
            let addr = usize::from_str_radix(addr.trim_start_matches("0x"), 16)
                .map_err(|_| "bad addr")?;
            let len = a.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(64);
            let (_, h, name, base) = attach()?;
            let buf = unsafe { process::read_bytes(h, addr, len) }
                .ok_or_else(|| "read failed".to_string())?;
            println!("module={name} base=0x{base:X} dump@0x{addr:X} len={len}");
            for (i, chunk) in buf.chunks(16).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' })
                    .collect();
                println!("{:04X}  {}  {}", i * 16, hex.join(" "), ascii);
            }
            Ok(())
        }
        "hook-ext" => {
            use windows_sys::Win32::System::Memory::{VirtualAllocEx, VirtualProtectEx};
            const MEM_COMMIT: u32 = 0x1000;
            const MEM_RESERVE: u32 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u32 = 0x40;
            const FN_RVA: usize = 0xA1A35E;

            let pid = process::find_process("re2.exe").ok_or("re2.exe is not running")?;
            let h = process::open_process(pid).ok_or("could not open re2")?;
            let mods = process::modules(pid);
            let base = mods
                .iter()
                .find(|(n, _, _)| n.to_lowercase().ends_with("re2.exe"))
                .map(|(_, b, _)| *b)
                .or_else(|| mods.first().map(|(_, b, _)| *b))
                .ok_or("no re2 module base")?;
            let fn_addr = base + FN_RVA;
            println!("pid={pid} re2 base=0x{base:X} hook@0x{fn_addr:X}");

            let mut cave = 0usize;
            const STEP: usize = 0x0100_0000;
            let mut hint = fn_addr.wrapping_sub(0x0800_0000);
            while hint > 0x0000_0001_0000_0000 {
                let r = unsafe {
                    VirtualAllocEx(
                        h,
                        hint as *mut _,
                        0x200,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    ) as usize
                };
                if r != 0 {
                    let rel = (r as i64) - (fn_addr as i64 + 5);
                    if rel.unsigned_abs() < (1i64 << 31) as u64 {
                        cave = r;
                        break;
                    }
                }
                hint = hint.wrapping_sub(STEP);
            }
            if cave == 0 {
                process::close_process(h);
                return Err("no allocatable cave within ±2GB of hook site".to_string());
            }
            let code = cave + 0x10;
            let flag = cave;

            let mut s = Vec::<u8>::with_capacity(64);
            s.extend_from_slice(&[0x48, 0x8B, 0x8E, 0x30, 0x02, 0x00, 0x00]); // mov rcx,[rsi+0x230]
            s.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx,rcx
            let jz = s.len();
            s.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // jz cont
            let cmp = s.len();
            s.extend_from_slice(&[0x80, 0x3D, 0, 0, 0, 0, 0x01]); // cmp byte[rip+d],1
            let jne = s.len();
            s.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne cont
            s.extend_from_slice(&[0x50, 0x53]); // push rax, push rbx
            s.extend_from_slice(&[0x48, 0x8D, 0x59, 0x58]); // lea rbx,[rcx+0x58]
            s.extend_from_slice(&[0x8B, 0x43, 0xFC]); // mov eax,[rbx-4]
            s.extend_from_slice(&[0x89, 0x03]); // mov [rbx],eax
            s.extend_from_slice(&[0x5B, 0x58]); // pop rbx, pop rax
            let cont = s.len();
            s.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]); // jmp [rip+0]

            let jz_end = (code + jz + 6) as i64;
            let rel = (code + cont) as i64 - jz_end;
            s[jz + 2..jz + 6].copy_from_slice(&(rel as i32).to_le_bytes());

            let cmp_end = (code + cmp + 7) as i64;
            let disp = flag as i64 - cmp_end;
            s[cmp + 2..cmp + 6].copy_from_slice(&(disp as i32).to_le_bytes());

            let jne_end = (code + jne + 6) as i64;
            let rel2 = (code + cont) as i64 - jne_end;
            s[jne + 2..jne + 6].copy_from_slice(&(rel2 as i32).to_le_bytes());

            s.extend_from_slice(&(fn_addr + 7).to_le_bytes());

            if process::write_bytes(h, cave, &[0u8]) // flag = disabled
                && process::write_bytes(h, code, &s)
            {
                println!("cave=0x{cave:X} stub={} bytes written", s.len());
            } else {
                process::close_process(h);
                return Err("stub write failed".to_string());
            }

            let mut old = 0u32;
            let ok_vp = unsafe {
                VirtualProtectEx(h, fn_addr as _, 7, PAGE_EXECUTE_READWRITE, &mut old) != 0
            };
            if !ok_vp {
                process::close_process(h);
                return Err(format!("VirtualProtectEx failed (error 0x{:X})", unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
            let mut patch = [0u8; 7];
            patch[0] = 0xE9;
            let rel = code as i64 - (fn_addr as i64 + 5);
            patch[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            patch[5] = 0x90;
            patch[6] = 0x90;
            let ok_w = process::write_bytes(h, fn_addr, &patch);
            let restore = old;
            let _ = unsafe { VirtualProtectEx(h, fn_addr as _, 7, restore, &mut old) };
            process::close_process(h);
            if !ok_w {
                return Err("patch write failed".to_string());
            }
            println!(
                "hooked. flag=0x{flag:X} (writeb 0x{flag:X} 1 to enable infinite health)"
            );
            Ok(())
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}