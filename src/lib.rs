#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub mod zoom;

#[ctor::ctor]
fn safe_setup() {
}