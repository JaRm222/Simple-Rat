use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::{mem, ptr, thread};
use std::ptr::read;
use std::sync::{Arc, Mutex};
use std::thread::Thread;
use windows::core::imp::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_DEBUG_REGISTERS_ARM, CONTEXT_DEBUG_REGISTERS_ARM64, CONTEXT_DEBUG_REGISTERS_X86, CONTEXT_FLAGS, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, IMAGE_NT_HEADERS64, M128A, WOW64_CONTEXT, WOW64_CONTEXT_DEBUG_REGISTERS, WOW64_CONTEXT_FLAGS, WOW64_CONTEXT_FULL, XSAVE_FORMAT};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_INFORMATION_CLASS, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, EXCEPTION_SINGLE_STEP, FALSE, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_SUCCESS};
use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree};
use windows::Win32::System::SystemInformation::GetTickCount64;
use crate::winsdk::{get_func_from_exports, get_ssn, nt_query_thread_info};
use crate::winsdk::get_syscall_address;

#[link(name = "kernel32")]
extern "system" {
    fn SetThreadContext(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL;
    fn AddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
    ) -> *mut std::ffi::c_void;
}
#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: NTSTATUS,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}
#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}
#[repr(C)]
pub struct CONTEXT {

    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: CONTEXT_FLAGS,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: *const c_void,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

pub fn get_main_thread_id() -> Option<u32> {
    unsafe {
        let nt_thread_info_addy = get_func_from_exports("ntdll.dll", "NtQueryInformationThread").unwrap();

        let ssn = get_ssn(nt_thread_info_addy);
        println!("ssn {}", ssn);
        let syscall_addy = get_syscall_address(nt_thread_info_addy);

        let proc_addy = GetModuleHandleW(PCWSTR::null()).unwrap().0;

        let dos_header = read(proc_addy as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            panic!("Magic does not match");
        }

        let nt_header = read(proc_addy.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
        if nt_header.Signature != IMAGE_NT_SIGNATURE {
            panic!("Signature does not match");
        }

        let entry_point_addy = proc_addy as usize + nt_header.OptionalHeader.AddressOfEntryPoint as usize;

        let h_thread_query = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok().unwrap();
        if h_thread_query == INVALID_HANDLE_VALUE {
            println!("Couldnt create snapshot");
            return None;
        }

        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(h_thread_query, &mut te).is_ok() {
            while Thread32Next(h_thread_query, &mut te).is_ok() {

                let h_thread_handle = match OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID) {
                    Ok(handle) => {handle},
                    Err(e) => {continue;}
                };

                if h_thread_handle == INVALID_HANDLE_VALUE {
                    continue;
                }

                let mut len: u32 = 0;
                let mut thread_start_addy: usize = 0;

                let status = nt_query_thread_info(
                    h_thread_handle.0,
                    THREAD_INFORMATION_CLASS(9).0, // ThreadQuerySetWin32StartAddress
                    &mut thread_start_addy as *mut _ as *mut c_void,
                    std::mem::size_of::<usize>() as u32,
                    &mut len,
                    ssn,
                    syscall_addy,
                );

                if status == STATUS_SUCCESS && entry_point_addy == thread_start_addy {
                    println!("FOUND!");
                    CloseHandle(h_thread_handle.0);
                    CloseHandle(h_thread_query.0);
                    return Some(te.th32ThreadID);
                }

                CloseHandle(h_thread_handle.0);


            }
        }else{
            return None;
        }

        CloseHandle(h_thread_query.0);
        None
    }
}



/*

    https://ling.re/hardware-breakpoints/

    Sets the linked list prev node to the next node
    Some process -> Our process -> Some process
    Some process -> Some process


    Hook NtQuerySystemInformation ( I use hardware breakpoints )
    Save the parameters
    Call NtQuerySystemInformation
    Remove our process from the list
    Set the buffer

*/

pub fn set_hardware_bp(main_thrd_id: u32, target_addy: usize)
{

    /*
        Get our thread and suspend it
        1) Get Thread context
        2) Set Dr0 to our target address (syscall instruction)
        3) set dr7 to enable 1 << 0
        4) Suspend the thread
        5) Set thread context to ours
        6) Resume thread
        7) Add exception handler to ours
    */
    unsafe {
        let main_thread_handle = unsafe { OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, main_thrd_id).unwrap()};
        if main_thread_handle == INVALID_HANDLE_VALUE {
            panic!("Couldnt open thread")
        }

        //https://github.com/microsoft/win32metadata/issues/1412

        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_DEBUG_REGISTERS_ARM | CONTEXT_DEBUG_REGISTERS_X86 | CONTEXT_DEBUG_REGISTERS_ARM64;
        context.Dr0 = target_addy as u64;
        context.Dr7 = 0x00000001;

        println!("Suspending Thread");
        SuspendThread(main_thread_handle);
        println!("Setting thread context");
        let res = SetThreadContext(main_thread_handle, &mut context);

        println!("Resuming thread");
        ResumeThread(main_thread_handle);

    }
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
        println!("Hardware breakpoint hit!");

        // Need to clear the thread context

        return EXCEPTION_CONTINUE_EXECUTION
    }

    EXCEPTION_CONTINUE_SEARCH
}

fn set_exception_handler() {
    unsafe {
        AddVectoredExceptionHandler(1, exception_handler);
    }
}

#[cfg(target_arch = "x86_64")]
pub fn hardware_bp(target_addy: usize)
{
    println!("Setting exception handler");
    set_exception_handler();


    let main_thread_id = match get_main_thread_id() {
        None => {panic!("Couldn't get main thread")}
        Some(id) => {id}
    };

    let handle = thread::spawn(move || {
        set_hardware_bp(main_thread_id, target_addy);
    });

    return
}