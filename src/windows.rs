use std::ffi::c_void;
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use minhook_sys::*;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HMODULE,
    call_reason: u32,
    reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            std::thread::spawn(|| {
                unsafe { 
                    initialize(); 
                    crate::zoom::initialize();
                }
            });
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }
    BOOL::from(true)
}

unsafe fn initialize() {
    if MH_Initialize() != MH_OK {
        return;
    }
}
