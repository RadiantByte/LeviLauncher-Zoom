use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use minhook_sys::*;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_C};

static ORIGINAL_RENDER_LEVEL: AtomicUsize = AtomicUsize::new(0);


const RENDER_LEVEL_SIG: &[u8] = &[
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x29, 0x70, 0x00, 0x0F, 0x29, 0x78, 0x00, 0x44, 0x0F, 0x29, 0x40, 0x00, 0x44, 0x0F, 0x29, 0x48, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE8, 0x4C, 0x8B, 0xE2, 0x4C, 0x8B, 0xF9
];

const RENDER_LEVEL_MASK: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

#[repr(C)]
struct LevelRenderer {
    padding: [u8; 0x3F0],
    player: *mut LevelRendererPlayer,
}

#[repr(C)]
struct LevelRendererPlayer {
    padding_x: [u8; 0xF80],
    fov_x: f32,
    padding_y: [u8; 0xF94 - 0xF80 - 4],
    fov_y: f32,
}

static mut ZOOM_MODIFIER: f32 = 1.0;
static TARGET_ZOOM: f32 = 10.0;

unsafe extern "C" fn detour_render_level(level_renderer: *mut LevelRenderer, screen_context: *mut c_void, unk: *mut c_void) {
    let original_addr = ORIGINAL_RENDER_LEVEL.load(Ordering::Relaxed);
    if original_addr != 0 {
        let original: extern "C" fn(*mut LevelRenderer, *mut c_void, *mut c_void) = std::mem::transmute(original_addr);
        
        original(level_renderer, screen_context, unk);

        if !level_renderer.is_null() {
             let player = (*level_renderer).player;
             if !player.is_null() {
                 let is_c_pressed = GetAsyncKeyState(VK_C.0 as i32) & 0x8000u16 as i16 != 0;
                 
                 let target = if is_c_pressed { TARGET_ZOOM } else { 1.0 };
                 
                 
                 ZOOM_MODIFIER = ZOOM_MODIFIER + (target - ZOOM_MODIFIER) * 0.1;
                 
                 (*player).fov_x *= ZOOM_MODIFIER;
                 (*player).fov_y *= ZOOM_MODIFIER;
             }
        }
    }
}

pub unsafe fn initialize() {
    let base = windows::Win32::System::LibraryLoader::GetModuleHandleA(None).unwrap();
    
    let dos_header = base.0 as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    let nt_headers = (base.0 as usize + (*dos_header).e_lfanew as usize) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    
    let memory_slice = std::slice::from_raw_parts(base.0 as *const u8, size_of_image);
    
    if let Some(offset) = find_pattern(memory_slice, RENDER_LEVEL_SIG, RENDER_LEVEL_MASK) {
        let target_addr = (base.0 as usize + offset) as *mut c_void;
        

        
        let mut original: *mut c_void = std::ptr::null_mut();
        if MH_CreateHook(target_addr, detour_render_level as *mut c_void, &mut original) == MH_OK {
            ORIGINAL_RENDER_LEVEL.store(original as usize, Ordering::Relaxed);
            MH_EnableHook(target_addr);
        }
    }
}

fn find_pattern(data: &[u8], pattern: &[u8], mask: &[u8]) -> Option<usize> {
    if pattern.len() != mask.len() {
        return None;
    }
    
    for i in 0..data.len() - pattern.len() {
        let mut found = true;
        for j in 0..pattern.len() {
            if mask[j] == 0xFF && data[i + j] != pattern[j] {
                found = false;
                break;
            }
        }
        if found {
            return Some(i);
        }
    }
    None
}
