#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]
#![windows_subsystem="windows"]
#![feature(type_ascription)]


use core::arch::asm;
use core::ptr::{null_mut};
use obfstr::bytes::{keystream, obfuscate};
use obfstr::obfstr;

mod binds;
mod utils;
use binds::*;
use utils::*;
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
//const KERNEL32_DLL: &str = concat!("KERNEL32.DLL", "\0");
const USER32_DLL: &str = concat!("user32.dll", "\0");
const LoadLibraryA_: &str = concat!("LoadLibraryA", "\0");
const GetProcAddress_: &str = concat!("GetProcAddress", "\0");
const MessageBoxA_: &str = concat!("MessageBoxA", "\0");
//const GetComputerName_: &str = concat!("GetComputerName", "\0");

pub type LoadLibraryAFn = extern "system" fn(lpFileName: LPCSTR) -> PVOID;
pub type GetProcAddressFn = extern "system" fn(hmodule: PVOID, name: LPCSTR) -> PVOID;
pub type MessageBoxAFn = extern "system" fn(h: PVOID, text: LPCSTR, cation: LPCSTR, t: u32) -> u32;
//pub type GetComputerNameFn = extern "system" fn(idk: LPSTR, idk2: DWORD) -> u32;
#[no_mangle]
pub extern "C" fn main() /* -> ! */ {
    unsafe {
        asm!("mov rcx, 0", "mov rdx, 0",);
    }
  //  obfuscate(KERNEL32_STR.as_slice(), &KERNEL32_STR);

    let kernel32_str: &[u16; 13] = obfstr::wide!("KERNEL32.DLL\0");
    let kernel32_ptr = get_module_by_name(kernel32_str.as_ptr());
    let load_library_ptr = get_func_by_name(kernel32_ptr, obfstr!(LoadLibraryA_).as_ptr());
    let get_proc = get_func_by_name(kernel32_ptr, obfstr!(GetProcAddress_).as_ptr());
   // let get_name = get_func_by_name(kernel32_ptr, GetComputerName_.as_ptr());
    let LoadLibraryA: LoadLibraryAFn = unsafe { core::mem::transmute(load_library_ptr) };

    unsafe { asm!("and rsp, ~0xf") };
    let u32_dll = LoadLibraryA(obfstr!(USER32_DLL).as_ptr() as *const i8);
    let GetProcAddress: GetProcAddressFn = unsafe { core::mem::transmute(get_proc) };
    let message_box_ptr = GetProcAddress(u32_dll, obfstr!(MessageBoxA_).as_ptr() as *const i8);
    let MessageBoxA: MessageBoxAFn = unsafe { core::mem::transmute(message_box_ptr) };
 //   let GetComputerName: GetComputerNameFn = unsafe { core::mem::transmute(get_name)};
  //  let name_output = GetComputerName("\0".as_ptr() as *mut i8: LPSTR, 32767);
    MessageBoxA(
        null_mut(),
        obfstr!("Message\0").as_ptr() as *const i8,
        obfstr!("Title\0").as_ptr() as _,
        0x20,
    );
    // loop {}
}

fn get_module_by_name(module_name: *const u16) -> PVOID {
    let peb: *mut PEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
        );
        let ldr = (*peb).Ldr;
        let list_entry = &((*ldr).InLoadOrderModuleList);
        let mut cur_module: *const LDR_DATA_TABLE_ENTRY = &list_entry as *const _ as *const _;
        loop {
            if cur_module.is_null() || (*cur_module).BaseAddress.is_null() {
                //todo: break
            }
            let cur_name = (*cur_module).BaseDllName.Buffer;
            if !cur_name.is_null() {
                if compare_raw_str(module_name, cur_name) {
                    return (*cur_module).BaseAddress;
                }
            }
            let flink = (*cur_module).InLoadOrderModuleList.Flink;
            cur_module = flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

fn get_func_by_name(module: PVOID, func_name: *const u8) -> PVOID {
    let idh: *const IMAGE_DOS_HEADER = module as *const _;
    unsafe {
        if (*idh).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }
        let e_lfanew = (*idh).e_lfanew;
        let nt_headers: *const IMAGE_NT_HEADERS =
            (module as *const u8).offset(e_lfanew as isize) as *const _;
        let op_header = &(*nt_headers).OptionalHeader;
        let virtual_addr = (&op_header.DataDirectory[0]).VirtualAddress;
        let export_dir: *const IMAGE_EXPORT_DIRECTORY =
            (module as *const u8).offset(virtual_addr as _) as _;
        let number_of_names = (*export_dir).NumberOfNames;
        let addr_of_funcs = (*export_dir).AddressOfFunctions;
        let addr_of_names = (*export_dir).AddressOfNames;
        let addr_of_ords = (*export_dir).AddressOfNameOrdinals;
        for i in 0..number_of_names {
            let name_rva_p: *const DWORD =
                (module as *const u8).offset((addr_of_names + i * 4) as isize) as *const _;
            let name_index_p: *const WORD =
                (module as *const u8).offset((addr_of_ords + i * 2) as isize) as *const _;
            let name_index = name_index_p.as_ref().unwrap();
            let mut off: u32 = (4 * name_index) as u32;
            off = off + addr_of_funcs;
            let func_rva: *const DWORD = (module as *const u8).offset(off as _) as *const _;

            let name_rva = name_rva_p.as_ref().unwrap();
            let curr_name = (module as *const u8).offset(*name_rva as isize);

            if *curr_name == 0 {
                continue;
            }
            if compare_raw_str(func_name, curr_name) {
                let res = (module as *const u8).offset(*func_rva as isize);
                return res as _;
            }
        }
    }
    return null_mut();
}
