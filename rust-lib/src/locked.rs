//! Key bytes held for an unlock: locked into RAM where the system allows it, wiped on drop.

use zeroize::Zeroize;

pub struct LockedBytes(Box<[u8]>);

impl LockedBytes {
    pub fn new(bytes: &[u8]) -> Self {
        let held = LockedBytes(bytes.to_vec().into_boxed_slice());
        // Best effort: a refused lock leaves the bytes usable, only swappable.
        sys::lock(&held.0);
        keep_out_of_core_dumps();
        held
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
        sys::unlock(&self.0);
    }
}

/// Linux: a process holding an unlocked key writes no core dump.
fn keep_out_of_core_dumps() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(unix)]
mod sys {
    pub fn lock(b: &[u8]) {
        unsafe { libc::mlock(b.as_ptr().cast(), b.len()) };
    }
    pub fn unlock(b: &[u8]) {
        unsafe { libc::munlock(b.as_ptr().cast(), b.len()) };
    }
}

#[cfg(windows)]
mod sys {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    pub fn lock(b: &[u8]) {
        unsafe { VirtualLock(b.as_ptr().cast(), b.len()) };
    }
    pub fn unlock(b: &[u8]) {
        unsafe { VirtualUnlock(b.as_ptr().cast(), b.len()) };
    }
}

#[cfg(not(any(unix, windows)))]
mod sys {
    pub fn lock(_: &[u8]) {}
    pub fn unlock(_: &[u8]) {}
}
