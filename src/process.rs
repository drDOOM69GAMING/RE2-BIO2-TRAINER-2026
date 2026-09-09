use std::ffi::c_void;
use std::mem;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::Threading::OpenProcess;

pub type ProcessHandle = isize;

fn to_ptr(h: ProcessHandle) -> HANDLE {
    h as HANDLE
}

pub fn open_process(pid: u32) -> Option<ProcessHandle> {
    const RIGHTS: u32 = 0x0008 | 0x0010 | 0x0020 | 0x0400;
    unsafe {
        let h = OpenProcess(RIGHTS, 0, pid);
        if h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(h as isize)
        }
    }
}

pub fn close_process(h: ProcessHandle) {
    unsafe {
        CloseHandle(to_ptr(h));
    }
}

pub fn find_process(process_name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut result = None;
        let mut first = Process32FirstW(snap, &mut entry);
        while first != 0 {
            let name = String::from_utf16_lossy(&entry.szExeFile)
                .to_lowercase()
                .trim_end_matches('\0')
                .to_string();
            if name.eq_ignore_ascii_case(process_name) {
                result = Some(entry.th32ProcessID);
                break;
            }
            first = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
        result
    }
}

pub fn modules(pid: u32) -> Vec<(String, usize, usize)> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut first = Module32FirstW(snap, &mut entry);
        while first != 0 {
            let name = String::from_utf16_lossy(&entry.szModule)
                .to_lowercase()
                .trim_end_matches('\0')
                .to_string();
            let base = entry.modBaseAddr as usize;
            let size = entry.modBaseSize as usize;
            out.push((name, base, size));
            first = Module32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
        out
    }
}

pub unsafe fn readable_regions(h: ProcessHandle) -> Vec<(usize, usize)> {
    const MEM_COMMIT: u32 = 0x1000;
    let mut out = Vec::new();
    let mut addr: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
        let n = VirtualQueryEx(
            to_ptr(h),
            addr as *const c_void,
            &mut mbi,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if n == 0 {
            break;
        }
        let len = mbi.RegionSize;
        if len == 0 {
            break;
        }
        let readable = match mbi.Protect & 0xFF {
            0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80 => true,
            _ => false,
        };
        if mbi.State == MEM_COMMIT && readable && mbi.Protect & 0x100 == 0 {
            out.push((addr, len));
        }
        addr = match addr.checked_add(len) {
            Some(a) => a,
            None => break,
        };
    }
    out
}

pub unsafe fn read_bytes(h: ProcessHandle, addr: usize, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut n = 0usize;
    let ok = ReadProcessMemory(
        to_ptr(h),
        addr as *const c_void,
        buf.as_mut_ptr().cast(),
        len,
        &mut n,
    );
    if ok != 0 && n == len {
        Some(buf)
    } else {
        None
    }
}

pub unsafe fn read_memory<T: Copy>(h: ProcessHandle, addr: usize) -> Option<T> {
    let mut buf: T = mem::zeroed();
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        to_ptr(h),
        addr as *const c_void,
        &mut buf as *mut T as *mut c_void,
        mem::size_of::<T>(),
        &mut read,
    );
    if ok != 0 && read == mem::size_of::<T>() {
        Some(buf)
    } else {
        None
    }
}

pub unsafe fn write_memory<T: Copy>(h: ProcessHandle, addr: usize, value: &T) -> bool {
    let mut written = 0usize;
    let ok = WriteProcessMemory(
        to_ptr(h),
        addr as *const c_void,
        (value as *const T).cast::<c_void>(),
        mem::size_of::<T>(),
        &mut written,
    );
    ok != 0 && written == mem::size_of::<T>()
}

pub fn write_bytes(h: ProcessHandle, addr: usize, data: &[u8]) -> bool {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            to_ptr(h),
            addr as *const c_void,
            data.as_ptr().cast::<c_void>(),
            data.len(),
            &mut written,
        )
    };
    ok != 0 && written == data.len()
}

pub unsafe fn resolve_chain(h: ProcessHandle, base: usize, offsets: &[isize]) -> Option<usize> {
    let mut addr = base;
    for (i, off) in offsets.iter().enumerate() {
        let next = (addr as isize).wrapping_add(*off) as usize;
        if i + 1 == offsets.len() {
            return Some(next);
        }
        addr = read_memory::<usize>(h, next)?;
    }
    Some(addr)
}