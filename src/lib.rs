//! A more efficient, no_std secp256k1 public-key recovery for the Solana SVM.
//!
//! On `target_os = "solana"` or `target_arch = "bpf"`, recovery routes through
//! the `sol_secp256k1_recover` syscall. Off-Solana, it falls through to the
//! `k256` crate so the same APIs work in host code (tests, off-chain
//! tooling). The Solana implementation costs ~25006 CUs, vs ~25193 CUs for
//! `solana_program::secp256k1_recover::secp256k1_recover`.
#![no_std]

use core::mem::MaybeUninit;

use solana_program_error::ProgramError;

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// Length of a message digest accepted by `secp256k1_recover`, in bytes.
pub const HASH_LENGTH: usize = 32;
/// Length of a compact (r, s) ECDSA signature, in bytes.
pub const SECP256K1_SIGNATURE_SIZE: usize = 64;
/// Length of an uncompressed secp256k1 public key without the 0x04 prefix.
pub const SECP256K1_PUBKEY_SIZE: usize = 64;
/// Length of a compact ECDSA signature plus a one-byte recovery id.
pub const SECP256K1_RECOVERABLE_SIGNATURE_SIZE: usize = 65;

#[cfg(all(
    any(target_arch = "bpf", target_os = "solana"),
    not(feature = "static-syscalls")
))]
unsafe extern "C" {
    fn sol_secp256k1_recover(
        hash: *const u8,
        recovery_id: u64,
        signature: *const u8,
        result: *mut u8,
    ) -> u64;
}

#[cfg(all(
    any(target_arch = "bpf", target_os = "solana"),
    feature = "static-syscalls"
))]
#[inline(always)]
unsafe fn sol_secp256k1_recover(
    hash: *const u8,
    recovery_id: u64,
    signature: *const u8,
    result: *mut u8,
) -> u64 {
    // murmur3_32(b"sol_secp256k1_recover", 0) — precomputed
    const SOL_SECP256K1_RECOVER_ID: usize = 0x17e40350;
    let syscall: extern "C" fn(*const u8, u64, *const u8, *mut u8) -> u64 =
        unsafe { core::mem::transmute(SOL_SECP256K1_RECOVER_ID) };
    syscall(hash, recovery_id, signature, result)
}

/// Recover the secp256k1 public key that produced `signature` over the
/// pre-hashed message `hash`, given the parity bit `is_odd` of the recovered
/// y-coordinate.
///
/// Returns the 64-byte uncompressed public key (x ‖ y, no 0x04 prefix), or an
/// error if the signature is malformed or no point can be recovered.
#[cfg_attr(any(target_arch = "bpf", target_os = "solana"), inline(always))]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
pub fn secp256k1_recover(
    hash: &[u8; HASH_LENGTH],
    is_odd: bool,
    signature: &[u8; SECP256K1_SIGNATURE_SIZE],
) -> Result<[u8; SECP256K1_PUBKEY_SIZE], ProgramError> {
    let mut out = MaybeUninit::<[u8; SECP256K1_PUBKEY_SIZE]>::uninit();
    unsafe {
        if sol_secp256k1_recover(
            hash.as_ptr(),
            is_odd as u64,
            signature.as_ptr(),
            out.as_mut_ptr() as *mut u8,
        ) == 0
        {
            Ok(out.assume_init())
        } else {
            Err(ProgramError::InvalidArgument)
        }
    }
}

/// Recover without checking the syscall return code.
///
/// On invalid inputs the returned bytes are unspecified. Use this only when
/// the caller has already validated the signature, or when garbage output is
/// acceptable (e.g. inside a larger check that compares the result against a
/// known pubkey).
#[cfg_attr(any(target_arch = "bpf", target_os = "solana"), inline(always))]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
pub fn secp256k1_recover_unchecked(
    hash: &[u8; HASH_LENGTH],
    is_odd: bool,
    signature: &[u8; SECP256K1_SIGNATURE_SIZE],
) -> [u8; SECP256K1_PUBKEY_SIZE] {
    let mut out = MaybeUninit::<[u8; SECP256K1_PUBKEY_SIZE]>::uninit();
    unsafe {
        sol_secp256k1_recover(
            hash.as_ptr(),
            is_odd as u64,
            signature.as_ptr(),
            out.as_mut_ptr() as *mut u8,
        );
        out.assume_init()
    }
}

/// Host fallback: recover via the `k256` crate. Mirrors the on-chain return
/// shape (64-byte uncompressed pubkey without the 0x04 prefix).
#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub fn secp256k1_recover(
    hash: &[u8; HASH_LENGTH],
    is_odd: bool,
    signature: &[u8; SECP256K1_SIGNATURE_SIZE],
) -> Result<[u8; SECP256K1_PUBKEY_SIZE], ProgramError> {
    let parsed = Signature::from_slice(signature).map_err(|_| ProgramError::InvalidArgument)?;

    // The on-chain syscall accepts high-S signatures, but k256's recovery
    // path requires low-S. Normalizing flips s = n - s, which negates the
    // recovered point's y-coordinate — so flip the parity to match.
    let (signature, is_odd) = match parsed.normalize_s() {
        Some(normalized) => (normalized, !is_odd),
        None => (parsed, is_odd),
    };

    let recovery_id =
        RecoveryId::try_from(is_odd as u8).map_err(|_| ProgramError::InvalidArgument)?;

    let verifying_key = VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let encoded = verifying_key.to_encoded_point(false);
    let recovered = encoded.as_bytes();

    let mut pubkey = MaybeUninit::<[u8; SECP256K1_PUBKEY_SIZE]>::uninit();
    unsafe {
        // Skip the leading 0x04 uncompressed-point tag.
        core::ptr::copy_nonoverlapping(
            recovered.as_ptr().add(1),
            pubkey.as_mut_ptr() as *mut u8,
            SECP256K1_PUBKEY_SIZE,
        );
        Ok(pubkey.assume_init())
    }
}

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub fn secp256k1_recover_unchecked(
    hash: &[u8; HASH_LENGTH],
    is_odd: bool,
    signature: &[u8; SECP256K1_SIGNATURE_SIZE],
) -> [u8; SECP256K1_PUBKEY_SIZE] {
    secp256k1_recover(hash, is_odd, signature).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_recover() {
        let message_digest: [u8; 32] = [
            0x6b, 0x37, 0x78, 0xa6, 0x4f, 0x26, 0x75, 0xf3, 0xf7, 0x6b, 0xf9, 0xf3, 0x5a, 0xf1,
            0xfc, 0x67, 0x37, 0x59, 0xed, 0x17, 0xae, 0xd8, 0x6d, 0xd5, 0x6c, 0xa3, 0x6c, 0x2b,
            0xfd, 0x7e, 0xb0, 0xf9,
        ];

        let signature_bytes: [u8; 64] = [
            0xd0, 0x34, 0xc9, 0x8a, 0xf3, 0x27, 0x4a, 0xd9, 0x3f, 0x3c, 0x8c, 0xe9, 0x44, 0xbb,
            0xc1, 0x7b, 0x11, 0xb6, 0xaa, 0x17, 0x0c, 0x5f, 0x09, 0x7e, 0xd9, 0x86, 0x87, 0xfa,
            0x0d, 0x93, 0x34, 0x7c, 0xa2, 0x31, 0x8c, 0xee, 0xa2, 0x00, 0x2c, 0xab, 0xa3, 0x8e,
            0xfb, 0xba, 0x3b, 0xf8, 0xef, 0x8d, 0x43, 0x23, 0x6a, 0x6e, 0xdc, 0x33, 0xc0, 0x40,
            0x73, 0x4d, 0x8e, 0xb2, 0xed, 0x77, 0xf6, 0x08,
        ];

        let pubkey_bytes: [u8; 64] = [
            0x10, 0xb5, 0xd9, 0x02, 0x8e, 0xc8, 0x28, 0xa0, 0xf9, 0x11, 0x1e, 0x36, 0xf0, 0x46,
            0xaf, 0xa5, 0xa0, 0xc6, 0x77, 0x35, 0x73, 0x51, 0x09, 0x34, 0x26, 0xbc, 0xec, 0x10,
            0xc6, 0x63, 0xdb, 0x7d, 0x27, 0x17, 0x63, 0xc5, 0x6f, 0xcd, 0x87, 0xb7, 0x2d, 0x59,
            0xce, 0xaa, 0x5b, 0x9c, 0x3f, 0xd2, 0x12, 0x27, 0x88, 0xfe, 0x34, 0x47, 0x51, 0xa9,
            0xbd, 0xe3, 0x73, 0xf9, 0x03, 0xe5, 0xbb, 0x20,
        ];

        let key = secp256k1_recover(&message_digest, true, &signature_bytes).unwrap();
        assert_eq!(key, pubkey_bytes);

        let key = secp256k1_recover(&message_digest, false, &signature_bytes).unwrap();
        assert_ne!(key, pubkey_bytes);
    }
}
