/*─────────────────────────────────────────────────────────────────────────────*\
 | Repo: IndirectSyscalls (PoC)
 | URL: https://github.com/dutchpsycho/IndirectSyscalls
 |
 | Description:
 |   Usermode technique to resolve and invoke syscalls
 |   without relying on the exported NTAPI functions or executing through a raw memory stub.
 |   Instead of calling ntdll!Nt* exports, it:
 |
 |   - Identifies valid syscall stubs by matching known instruction prologues in ntdll
 |   - Extracts the system service number (SSN) from each stub
 |   - Caches syscall names and SSNs into a global table
 |   - Allows direct invocation of the syscall stub by function name
 |
 |   This avoids API hooks and simplifies syscall-level instrumentation or syscall testing.
 |
 | Target: Windows x64
 |
 | Author: Damon @ TITAN Softwork Solutions
\*─────────────────────────────────────────────────────────────────────────────*/

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]

use rustc_hash::FxHashMap;
use std::{
    ffi::CStr,
    os::raw::c_char,
    ptr::null_mut,
    slice,
    sync::OnceLock,
    mem,
};
use winapi::{
    shared::minwindef::ULONG,
    um::{
        libloaderapi::GetModuleHandleA,
        processthreadsapi::GetCurrentProcess,
        psapi::{GetModuleInformation, MODULEINFO},
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
            IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER,
        },
    },
};
use itertools::Itertools;

static SYSCALL_TABLE: OnceLock<FxHashMap<String, (u32, usize)>> = OnceLock::new();

const STATUS_SUCCESS: i32                 = 0;

#[inline(always)]
fn rva_to_ptr(
    base: *const u8,
    rva: usize,
    image_size: usize,
    sections: &[IMAGE_SECTION_HEADER],
    ctx: &str,
) -> Result<*const u8, String> {
    unsafe {
        if base.is_null() {
            return Err(format!("{}: base is null", ctx));
        }
        if rva >= image_size {
            return Err(format!("{}: RVA {:#X} >= image_size {:#X}", ctx, rva, image_size));
        }

        Ok(base.add(rva))
    }
}

fn extract(base: *const u8, image_size: usize) -> Result<(), String> {
    unsafe {
        let dos = &*(base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return Err("bad DOS magic".into());
        }

        let nt = {
            let off = dos.e_lfanew as usize;
            &*(base.add(off) as *const IMAGE_NT_HEADERS)
        };
        if nt.Signature != 0x0000_4550 {
            return Err("bad NT signature".into());
        }

        let nsec = nt.FileHeader.NumberOfSections as usize;
        let secs_ptr = base
            .add(dos.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS>())
            as *const IMAGE_SECTION_HEADER;
        let sections = slice::from_raw_parts(secs_ptr, nsec);

        let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
        let ed_ptr = rva_to_ptr(base, export_rva, image_size, sections, "export dir")? as *const IMAGE_EXPORT_DIRECTORY;
        let ed = &*ed_ptr;

        let names = rva_to_ptr(base, ed.AddressOfNames as usize, image_size, sections, "names")? as *const u32;
        let ords = rva_to_ptr(base, ed.AddressOfNameOrdinals as usize, image_size, sections, "ords")? as *const u16;
        let funcs = rva_to_ptr(base, ed.AddressOfFunctions as usize, image_size, sections, "funcs")? as *const u32;

        let mut map = FxHashMap::with_capacity_and_hasher(ed.NumberOfNames as usize, Default::default());

        for i in 0..(ed.NumberOfNames as usize) {
            let name_rva = *names.add(i) as usize;
            let name_ptr = rva_to_ptr(base, name_rva, image_size, sections, "fn name")? as *const c_char;
            let bytes = CStr::from_ptr(name_ptr).to_bytes();

            if !bytes.starts_with(b"Nt") { continue; }

            let ord = *ords.add(i) as usize;
            if ord >= ed.NumberOfFunctions as usize { continue; }
            let fn_rva = *funcs.add(ord) as usize;

            let sig_ptr = rva_to_ptr(base, fn_rva, image_size, sections, "stub")?;
            let sig = slice::from_raw_parts(sig_ptr, 8);

            let is_stub = matches!(
                sig,
                [0xB8, ..]
                | [0x4C, 0x8B, 0xD1, 0xB8, ..]
                | [0x4D, 0x8B, 0xD1, 0xB8, ..]
            );
            if !is_stub { continue; }

            let ssn = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
            let name = String::from_utf8_lossy(bytes).into_owned();

            map.insert(name, (ssn, fn_rva));
        }

        SYSCALL_TABLE.set(map).map_err(|_| "syscall table already initialized".into())
    }
}

#[inline]
fn get_syscall_table() -> &'static FxHashMap<String, (u32, usize)> {
    SYSCALL_TABLE.get().expect("syscall table uninitialized")
}

// PEB->LdrLoadedModules parse for ntdll.dll
#[inline]
fn init_syscalls() -> Result<(*const u8, usize), String> {
    unsafe {
        #[repr(C)]
        struct UnicodeString {
            length: u16,
            max_len: u16,
            buffer: *const u16,
        }

        #[repr(C)]
        struct ListEntry {
            flink: *const ListEntry,
            blink: *const ListEntry,
        }

        #[repr(C)]
        struct LdrDataTableEntry {
            in_load_order_links: ListEntry,
            in_mem_order_links: ListEntry,
            in_init_order_links: ListEntry,
            base_address: *const u8,
            _entry_point: *const u8,
            _size_of_image: u32,
            _pad0: u32,
            full_dll_name: UnicodeString,
            _base_dll_name: UnicodeString,
        }

        #[repr(C)]
        struct PebLdrData {
            _pad0: [usize; 2],
            in_mem_order_module_list: ListEntry,
        }

        #[repr(C)]
        struct Peb {
            _pad: [u8; 0x18],
            ldr: *const PebLdrData,
        }

        let peb: *const Peb;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);

        if peb.is_null() {
            return Err("PEB not found".into());
        }

        let ldr = (*peb).ldr;
        if ldr.is_null() {
            return Err("PEB.Ldr is null".into());
        }

        let list_head = &(*ldr).in_mem_order_module_list;
        let mut current = list_head.flink;

        while !current.is_null() && current != list_head as *const _ {
            let entry = current.cast::<LdrDataTableEntry>().as_ref().unwrap();

            let len = (entry.full_dll_name.length / 2) as usize;
            let name_slice = std::slice::from_raw_parts(entry.full_dll_name.buffer, len);
            let name = String::from_utf16_lossy(name_slice).to_ascii_lowercase();

            if name.contains("ntdll.dll") {
                let base = entry.base_address;
                if base.is_null() {
                    return Err("ntdll.dll base is null".into());
                }

                let dos = &*(base as *const IMAGE_DOS_HEADER);
                let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
                let size = nt.OptionalHeader.SizeOfImage as usize;

                extract(base, size)?;
                return Ok((base, size));
            }

            current = (*current).flink;
        }

        Err("ntdll.dll not found in loaded module list".into()) // will never happen
    }
}

#[inline(always)]
pub fn indirect_syscall(syscall_name: &str, args: &[u64]) -> Result<u64, String> {
    if args.len() > 16 {
        return Err("too many args: max is 16".into());
    }

    // resolve syscall address
    let (base, _) = { init_syscalls()? };
    let table = get_syscall_table();

    let (ssn, fn_rva) = *table
        .get(syscall_name)
        .ok_or_else(|| format!("{} not found in syscall table", syscall_name))?;

    let stub_ptr = unsafe { base.add(fn_rva) };

    // sanity: ptr must be aligned to at least 4 bytes
    if (stub_ptr as usize) % 4 != 0 {
        return Err(format!(
            "misaligned syscall stub: {:p} for {}",
            stub_ptr, syscall_name
        ));
    }

    // verify syscall ABI
    let sig = unsafe { slice::from_raw_parts(stub_ptr, 8) };
    let is_valid = matches!(
        sig,
        [0xB8, ..]
        | [0x4C, 0x8B, 0xD1, 0xB8, ..]
        | [0x4D, 0x8B, 0xD1, 0xB8, ..]
    );

    if !is_valid {
        return Err(format!("invalid or forwarded stub for '{}': {:02X?}", syscall_name, &sig[..std::cmp::min(sig.len(), 8)]));
    }

    let mut packed = [0u64; 16];
    packed[..args.len()].copy_from_slice(args);

    let ret = unsafe { type SysFn = extern "system" fn (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
        let syscall_fn: SysFn = std::mem::transmute(stub_ptr);
        syscall_fn(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8], packed[9], packed[10], packed[11], packed[12], packed[13], packed[14], packed[15],
        )
    };

    println!("indirect_syscall('{}') → NTSTATUS 0x{:08X} (ssn: 0x{:03X})", syscall_name, ret as u32, ssn);

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn NtQuerySystemInformation() {
        // allocate buffer
        let mut buf = vec![0u8; 0x10000];
        let mut retlen: u32 = 0;
    
        // call with correct pointer args
        let status = indirect_syscall(
            "NtQuerySystemInformation",
            &[
                5,                              // SystemProcessInformation
                buf.as_mut_ptr() as u64,        // SystemInformation
                buf.len() as u64,               // Length
                &mut retlen as *mut u32 as u64  // ReturnLength
            ]
        );
    
        assert!(status.is_ok());
    
        let code = status.unwrap() as u32;
        assert!(
            code == STATUS_SUCCESS as u32 ||
            code == 0xC0000004 // STATUS_INFO_LENGTH_MISMATCH
        );
    }    
}

fn main() {
    match indirect_syscall("NtYieldExecution", &[]) {
        Ok(code) => {
            println!("NtYieldExecution → NTSTATUS 0x{:08X}", code as u32);
            // STATUS_NO_YIELD_PERFORMED / 0x40000024L
        }
        Err(err) => {
            eprintln!("indirect_syscall failed: {}", err);
        }
    }
}