// ============================================================
// VOID-TUNNEL :: vt-core :: lib.rs
//
// Public API Surface and FFI Export Layer
// Exposes all subsystems to vt-transport, vt-deploy, and Tauri
//
// Author: Vladimir Unknown
// ============================================================

// ── Module Declarations ───────────────────────────────────────────────────────
pub mod crypto {
    pub mod chacha;
    pub mod ed25519;
    pub mod hmac;
    pub mod keygen;
    pub mod kdf;
}

pub mod padding {
    pub mod distributions;
    pub mod polymorphic;
}

pub mod tls {
    pub mod handshake_frag;
    pub mod ja4_spoof;
}

pub mod dns {
    pub mod doh;
    pub mod dot;
}

pub mod config {
    pub mod patcher;
    pub mod profiles;
    pub mod schema;
}

pub mod error;

// ── Re-exports for Ergonomic Use ─────────────────────────────────────────────
pub use error::{VtError, VtResult};
pub use config::schema::{
    Ja4Profile, Language, NodeCredentials, OperationalMode,
    PacketSplitConfig, ServerlessProvider, VoidTunnelConfig,
};
pub use crypto::keygen::KeyBundle;
pub use padding::distributions::PaddingParams;

// ── FFI C Interface ───────────────────────────────────────────────────────────
// Exposes a minimal, safe C ABI for Tauri IPC and mobile platform bridges.
// All FFI functions use raw pointer inputs/outputs with explicit length params.
// Errors are communicated via i32 return codes (0 = Ok, -1 = Error).

use std::ffi::{c_char, CStr, CString};
use std::ptr;

/// FFI: Generate a new deployment key bundle.
/// Caller is responsible for freeing the returned JSON string via
/// `vt_free_string`. Returns NULL on failure.
#[no_mangle]
pub extern "C" fn vt_generate_keybundle() -> *mut c_char {
    match crypto::keygen::generate_deployment_keybundle() {
        Ok(bundle) => {
            match serde_json::to_string(&bundle) {
                Ok(json) => CString::new(json)
                    .map(|s| s.into_raw())
                    .unwrap_or(ptr::null_mut()),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

/// FFI: Free a string previously returned by a vt_* FFI function.
/// MUST be called for every non-null pointer returned by FFI functions.
#[no_mangle]
pub extern "C" fn vt_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Safety: ptr was created by CString::into_raw() in this crate
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

/// FFI: Validate an HMAC token.
/// Returns 0 if valid, -1 if invalid/replayed.
///
/// # Safety
/// `secret_ptr` and `token_ptr` must be valid null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn vt_validate_hmac_token(
    secret_ptr: *const c_char,
    token_ptr: *const c_char,
) -> i32 {
    if secret_ptr.is_null() || token_ptr.is_null() {
        return -1;
    }

    let secret_str = match CStr::from_ptr(secret_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let token_str = match CStr::from_ptr(token_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let secret_bytes = match hex::decode(secret_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };

    match crypto::hmac::validate_token(&secret_bytes, token_str) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}