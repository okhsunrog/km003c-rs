//! Encrypted embedded protocol and firmware-service credentials.
//!
//! Each value stores AES-256-CBC ciphertext and its initialization vector (IV).
//! CBC zero padding is removed using the decoded array length. LazyLock decrypts
//! a value once, on first access, and retains the result for subsequent callers.
//! The encryption key is bundled too: this hides plaintext literals, not secrets
//! from someone who can inspect or run the application. No EXE or file is needed.
//! This storage envelope is independent of the device's wire encryption modes.

use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding},
};
use std::sync::LazyLock;

const AES_BLOCK_BYTES: usize = 16;
const KEY_ENCRYPTION_KEY: [u8; 32] = [
    0xd5, 0xeb, 0x9f, 0x34, 0xa5, 0x48, 0x2b, 0x72, 0xd7, 0x09, 0x94, 0xdc, 0xee, 0x92, 0x16, 0x67, 0xeb, 0xb5, 0xa2,
    0x59, 0xa2, 0x5e, 0x41, 0x8d, 0x8c, 0x93, 0x91, 0x58, 0x82, 0x9a, 0x62, 0x49,
];

/// AES-256-CBC ciphertext and the IV used to encrypt it.
struct EncryptedValue<const CIPHERTEXT_BYTES: usize> {
    ciphertext: [u8; CIPHERTEXT_BYTES],
    iv: [u8; AES_BLOCK_BYTES],
}

impl<const CIPHERTEXT_BYTES: usize> EncryptedValue<CIPHERTEXT_BYTES> {
    // Keep decoding at runtime, including optimized builds.
    #[inline(never)]
    fn decrypt<const PLAINTEXT_BYTES: usize>(&self) -> [u8; PLAINTEXT_BYTES] {
        assert!(CIPHERTEXT_BYTES.is_multiple_of(AES_BLOCK_BYTES));
        assert!(PLAINTEXT_BYTES <= CIPHERTEXT_BYTES);
        assert!(CIPHERTEXT_BYTES - PLAINTEXT_BYTES < AES_BLOCK_BYTES);
        let mut padded_plaintext = self.ciphertext;
        cbc::Decryptor::<Aes256>::new((&std::hint::black_box(KEY_ENCRYPTION_KEY)).into(), (&self.iv).into())
            .decrypt_padded::<NoPadding>(&mut padded_plaintext)
            .expect("embedded ciphertext must contain complete AES blocks");
        assert!(
            padded_plaintext[PLAINTEXT_BYTES..].iter().all(|&byte| byte == 0),
            "embedded value must have zero padding"
        );
        let mut plaintext = [0; PLAINTEXT_BYTES];
        plaintext.copy_from_slice(&padded_plaintext[..PLAINTEXT_BYTES]);
        plaintext
    }
}

const ENCRYPTED_STREAMING_AUTH_KEY_ENC: EncryptedValue<16> = EncryptedValue {
    ciphertext: [
        0x02, 0xbc, 0xae, 0x60, 0xcc, 0xfb, 0x45, 0x53, 0x83, 0xe7, 0xd6, 0x9d, 0x8c, 0xee, 0x3c, 0x40,
    ],
    iv: [
        0x12, 0x54, 0xd6, 0x38, 0xe7, 0x70, 0xbb, 0xbe, 0x61, 0x4b, 0x37, 0x7d, 0x77, 0xe1, 0x75, 0x07,
    ],
};

/// Streaming auth key enc, decrypted once on first use.
pub static STREAMING_AUTH_KEY_ENC: LazyLock<[u8; 16]> = LazyLock::new(|| ENCRYPTED_STREAMING_AUTH_KEY_ENC.decrypt());

const ENCRYPTED_STREAMING_AUTH_KEY_DEC: EncryptedValue<16> = EncryptedValue {
    ciphertext: [
        0x37, 0x7f, 0x3b, 0x21, 0xea, 0xa8, 0x43, 0xa0, 0x75, 0x50, 0xe0, 0x3f, 0x1d, 0x6d, 0xd4, 0xae,
    ],
    iv: [
        0x1e, 0x8b, 0x22, 0xb7, 0x5a, 0x51, 0x88, 0x39, 0xf1, 0xd9, 0x1e, 0xc9, 0xc3, 0x35, 0x10, 0xc8,
    ],
};

/// Streaming auth key dec, decrypted once on first use.
pub static STREAMING_AUTH_KEY_DEC: LazyLock<[u8; 16]> = LazyLock::new(|| ENCRYPTED_STREAMING_AUTH_KEY_DEC.decrypt());

const ENCRYPTED_MEMORY_READ_KEY: EncryptedValue<16> = EncryptedValue {
    ciphertext: [
        0x12, 0x93, 0x45, 0xaa, 0x53, 0x1c, 0x23, 0xd5, 0x86, 0x67, 0xce, 0xdf, 0x44, 0xc2, 0x05, 0xfe,
    ],
    iv: [
        0xec, 0x36, 0x07, 0x7b, 0xaa, 0x76, 0x13, 0xd8, 0x67, 0xcf, 0x71, 0xb1, 0x50, 0xeb, 0xa7, 0x77,
    ],
};

/// Memory read key, decrypted once on first use.
pub static MEMORY_READ_KEY: LazyLock<[u8; 16]> = LazyLock::new(|| ENCRYPTED_MEMORY_READ_KEY.decrypt());

#[cfg(feature = "firmware-catalog")]
const ENCRYPTED_OSS_ACCESS_KEY_ID: EncryptedValue<32> = EncryptedValue {
    ciphertext: [
        0xf7, 0xcc, 0x05, 0x4f, 0x34, 0x91, 0x5a, 0xdc, 0x82, 0x50, 0x02, 0xb4, 0x59, 0xc1, 0xb5, 0x09, 0xaf, 0x84,
        0xed, 0xbd, 0xc0, 0xd4, 0x38, 0xde, 0xde, 0xe3, 0xcf, 0x8a, 0x5c, 0xd0, 0x9f, 0x16,
    ],
    iv: [
        0x26, 0xae, 0xd4, 0xc7, 0x94, 0x2d, 0x10, 0x8b, 0xa9, 0x96, 0x99, 0xa6, 0x51, 0x2b, 0xbb, 0x64,
    ],
};

/// Oss access key id, decrypted once on first use.
#[cfg(feature = "firmware-catalog")]
pub(crate) static OSS_ACCESS_KEY_ID: LazyLock<[u8; 24]> = LazyLock::new(|| ENCRYPTED_OSS_ACCESS_KEY_ID.decrypt());

#[cfg(feature = "firmware-catalog")]
const ENCRYPTED_OSS_ACCESS_KEY_SECRET: EncryptedValue<32> = EncryptedValue {
    ciphertext: [
        0x0e, 0x1a, 0xc9, 0x9f, 0xd8, 0x7e, 0x11, 0x40, 0x2e, 0xf0, 0x77, 0x22, 0xa8, 0xab, 0x58, 0xc4, 0x04, 0xc6,
        0xd3, 0xc2, 0xa7, 0x2b, 0x50, 0x9e, 0xf4, 0xcb, 0x87, 0x67, 0x21, 0xbd, 0xc6, 0xda,
    ],
    iv: [
        0x58, 0xb5, 0x1e, 0xd9, 0xdb, 0x18, 0x79, 0xbe, 0x16, 0x66, 0x8a, 0x3f, 0x88, 0x7e, 0x2b, 0xb9,
    ],
};

/// Oss access key secret, decrypted once on first use.
#[cfg(feature = "firmware-catalog")]
pub(crate) static OSS_ACCESS_KEY_SECRET: LazyLock<[u8; 30]> =
    LazyLock::new(|| ENCRYPTED_OSS_ACCESS_KEY_SECRET.decrypt());

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt, KeyInit},
    };

    // Independently generated with OpenSSL from the original protocol keys.
    #[test]
    fn protocol_keys_match_original_wire_vectors() {
        let cipher = Aes128::new((&*STREAMING_AUTH_KEY_ENC).into());
        let mut block = [0; 16];
        cipher.encrypt_block((&mut block).into());
        assert_eq!(
            block,
            [
                0xf9, 0x84, 0xc0, 0xad, 0x7a, 0x46, 0xba, 0x91, 0x65, 0x39, 0x87, 0xe6, 0xc7, 0x6c, 0x5f, 0xc8
            ]
        );
        let cipher = Aes128::new((&*STREAMING_AUTH_KEY_DEC).into());
        let mut block = [0; 16];
        cipher.encrypt_block((&mut block).into());
        assert_eq!(
            block,
            [
                0x2b, 0x9c, 0x0d, 0x53, 0x8e, 0x50, 0x0f, 0xa7, 0xf7, 0xcb, 0x78, 0x94, 0x93, 0xfe, 0xce, 0x3e
            ]
        );
        let cipher = Aes128::new((&*MEMORY_READ_KEY).into());
        let mut block = [0; 16];
        cipher.encrypt_block((&mut block).into());
        assert_eq!(
            block,
            [
                0x27, 0x52, 0xeb, 0x11, 0x1d, 0xc1, 0x05, 0xd1, 0xe3, 0x72, 0x62, 0xf6, 0x46, 0x82, 0xae, 0xce
            ]
        );
    }
}
