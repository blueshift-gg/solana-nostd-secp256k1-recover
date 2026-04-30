#![no_std]
use core::mem::MaybeUninit;
#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
use k256::elliptic_curve::sec1::ToEncodedPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Secp256k1RecoverError {
    SignatureError,
    HashError,
    RecoveryError,
}

pub const SECP256K1_RECOVERABLE_SIGNATURE_SIZE: usize = 65;
pub const SECP256K1_SIGNATURE_SIZE: usize = 64;
pub const SECP256K1_PUBKEY_SIZE: usize = 64;
pub const HASH_LENGTH: usize = 32;

#[cfg(target_os = "solana")]
extern "C" {
    fn sol_secp256k1_recover(
        hash: *const [u8; 32],
        recovery_id: u64,
        signature: *const [u8; 64],
        result: *mut [u8; 64],
    ) -> u64;
}

#[inline(always)]
#[cfg(target_os = "solana")]
pub fn secp256k1_recover(
    hash: &[u8; 32],
    is_odd: bool,
    signature: &[u8; 64],
) -> Result<[u8; 64], Secp256k1RecoverError> {
    let mut out = MaybeUninit::<[u8; 64]>::uninit();
    unsafe {
        if sol_secp256k1_recover(
            hash.as_ptr() as *const [u8; 32],
            is_odd as u64,
            signature.as_ptr() as *const [u8; 64],
            out.as_mut_ptr() as *mut [u8; 64],
        ) == 0
        {
            Ok(out.assume_init())
        } else {
            Err(Secp256k1RecoverError::RecoveryError)
        }
    }
}

#[inline(always)]
#[cfg(target_os = "solana")]
pub fn secp256k1_recover_unchecked(
    hash: &[u8; 32],
    is_odd: bool,
    signature: &[u8; 64],
) -> [u8; 64] {
    let mut out = MaybeUninit::<[u8; 64]>::uninit();
    unsafe {
        sol_secp256k1_recover(
            hash.as_ptr() as *const [u8; 32],
            is_odd as u64,
            signature.as_ptr() as *const [u8; 64],
            out.as_mut_ptr() as *mut [u8; 64],
        );
        out.assume_init()
    }
}

#[inline(always)]
#[cfg(not(target_os = "solana"))]
pub fn secp256k1_recover(
    hash: &[u8; 32],
    is_odd: bool,
    signature: &[u8; 64],
) -> Result<[u8; 64], Secp256k1RecoverError> {
    // Parse the recoverable signature
    let mut recoverable_signature = [0u8;SECP256K1_RECOVERABLE_SIGNATURE_SIZE];
    recoverable_signature[..SECP256K1_SIGNATURE_SIZE].clone_from_slice(signature);
    recoverable_signature[SECP256K1_SIGNATURE_SIZE] = is_odd as u8;

    let signature: k256::ecdsa::recoverable::Signature =
        k256::ecdsa::recoverable::Signature::try_from(recoverable_signature.as_ref())
            .map_err(|_| Secp256k1RecoverError::SignatureError)?;

    // Recover the public key from the signature and message hash
    let binding = signature
        .recover_verify_key_from_digest_bytes(hash.into())
        .map_err(|_| Secp256k1RecoverError::RecoveryError)?
        .to_encoded_point(false);

    let recovered_key = binding.as_bytes();

    // Use MaybeUninit to initialize the array
    let mut pubkey = MaybeUninit::<[u8; 64]>::uninit();

    unsafe {
        // Write the last 64 bytes of the uncompressed public key to the initialized memory
        core::ptr::copy_nonoverlapping(
            recovered_key.as_ptr().add(1), // Skip the first byte (0x04 prefix)
            pubkey.as_mut_ptr() as *mut u8,
            64,
        );

        // Return the safely initialized 64-byte array
        Ok(pubkey.assume_init())
    }
}

#[inline(always)]
#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub fn secp256k1_recover_unchecked(
    hash: &[u8; 32],
    is_odd: bool,
    signature: &[u8; 64],
) -> [u8; 64] {
    secp256k1_recover(hash, is_odd, signature).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_hash() {
        // Example 32-byte precomputed message digest (e.g., the result of a SHA-256 hash)
        let message_digest: [u8; 32] = [
            0x6b, 0x37, 0x78, 0xa6, 0x4f, 0x26, 0x75, 0xf3, 0xf7, 0x6b, 0xf9, 0xf3, 0x5a, 0xf1,
            0xfc, 0x67, 0x37, 0x59, 0xed, 0x17, 0xae, 0xd8, 0x6d, 0xd5, 0x6c, 0xa3, 0x6c, 0x2b,
            0xfd, 0x7e, 0xb0, 0xf9,
        ];

        // This is an example; in real use cases, you'll have this from signing.
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

        assert_ne!(key, pubkey_bytes)
    }
}
