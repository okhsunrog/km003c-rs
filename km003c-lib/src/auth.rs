//! Authentication module for KM003C device
//!
//! This module provides data structures and encryption helpers for the
//! StreamingAuth (0x4C) and MemoryRead (0x44) commands required for AdcQueue streaming.
//!
//! # Authentication Flow
//!
//! 1. Read HardwareID from device memory at 0x40010450 using MemoryRead (0x44)
//! 2. Send StreamingAuth (0x4C) with HardwareID embedded in encrypted payload
//! 3. Device validates and grants auth level 1 (AdcQueue access)
//!
//! # AES Keys
//!
//! - StreamingAuth encrypt (host→device): `Fa0b4tA25f4R038a`
//! - StreamingAuth decrypt (device→host): `FX0b4tA25f4R038a`
//! - MemoryRead: `Lh2yfB7n6X7d9a5Z`
//!
//! # Usage
//!
//! Use the `Packet::MemoryRead` and `Packet::StreamingAuth` variants from the
//! message module to send authentication commands. This module provides the
//! underlying encryption and data structures.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// AES-128 key for StreamingAuth encryption (host → device)
pub const STREAMING_AUTH_KEY_ENC: &[u8; 16] = b"Fa0b4tA25f4R038a";

/// AES-128 key for StreamingAuth decryption (device → host)
pub const STREAMING_AUTH_KEY_DEC: &[u8; 16] = b"FX0b4tA25f4R038a";

/// AES-128 key for MemoryRead command
pub const MEMORY_READ_KEY: &[u8; 16] = b"Lh2yfB7n6X7d9a5Z";

/// Memory address where HardwareID is stored
pub const HARDWARE_ID_ADDRESS: u32 = 0x40010450;

/// Size of HardwareID in bytes
pub const HARDWARE_ID_SIZE: usize = 12;

/// Memory address for DeviceInfo1 (model, HW version, mfg date)
pub const DEVICE_INFO_ADDRESS: u32 = 0x00000420;

/// Memory address for FirmwareInfo (FW version, build date)
pub const FIRMWARE_INFO_ADDRESS: u32 = 0x00004420;

/// Memory address for CalibrationData (serial, UUID, timestamp)
pub const CALIBRATION_ADDRESS: u32 = 0x03000C00;

/// Size of info blocks (DeviceInfo, FirmwareInfo, Calibration)
pub const INFO_BLOCK_SIZE: usize = 64;

/// 12-byte Hardware ID read from device memory at 0x40010450
///
/// Structure:
/// - Bytes 0-5: Serial prefix (e.g., "071KBP" ASCII)
/// - Bytes 6-7: Separator (typically 0x0D 0xFF)
/// - Bytes 8-9: Device ID (little-endian u16)
/// - Bytes 10-11: Padding (typically 0xFF 0xFF)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareId {
    pub bytes: [u8; HARDWARE_ID_SIZE],
}

impl HardwareId {
    /// Create HardwareId from raw bytes
    pub fn from_bytes(bytes: [u8; HARDWARE_ID_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the serial prefix (first 6 bytes as ASCII string)
    pub fn serial_prefix(&self) -> Option<String> {
        let prefix = &self.bytes[0..6];
        if prefix.iter().all(|&b| b.is_ascii_alphanumeric()) {
            Some(String::from_utf8_lossy(prefix).to_string())
        } else {
            None
        }
    }

    /// Get the device ID (bytes 8-9 as little-endian u16)
    pub fn device_id(&self) -> u16 {
        u16::from_le_bytes([self.bytes[8], self.bytes[9]])
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; HARDWARE_ID_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Display for HardwareId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

/// Device information parsed from memory blocks
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    /// Model name (e.g., "KM003C")
    pub model: String,
    /// Hardware version (e.g., "2.1")
    pub hw_version: String,
    /// Manufacturing date (e.g., "2022.11.7")
    pub mfg_date: String,
    /// Firmware version (e.g., "1.9.9")
    pub fw_version: String,
    /// Firmware build date (e.g., "2025.9.22")
    pub fw_date: String,
    /// Serial ID from calibration (e.g., "007965")
    pub serial_id: String,
    /// UUID/hash from calibration
    pub uuid: String,
}

impl DeviceInfo {
    /// Parse DeviceInfo1 block (64 bytes from 0x420)
    ///
    /// Layout:
    /// - 0x00-0x0F: reserved
    /// - 0x10-0x1B: model (12 bytes, null-terminated)
    /// - 0x1C-0x27: hw_version (12 bytes, null-terminated)
    /// - 0x28-0x3F: mfg_date (24 bytes, null-terminated)
    pub fn parse_device_info(&mut self, data: &[u8]) {
        if data.len() >= 64 {
            self.model = extract_string(data, 0x10, 0x1C);
            self.hw_version = extract_string(data, 0x1C, 0x28);
            self.mfg_date = extract_string(data, 0x28, 0x40);
        }
    }

    /// Parse FirmwareInfo block (64 bytes from 0x4420)
    ///
    /// Layout:
    /// - 0x00-0x03: magic (0x00004000 or 0xFFFFFFFF if invalid)
    /// - 0x10-0x1B: model (12 bytes)
    /// - 0x1C-0x27: fw_version (12 bytes, null-terminated)
    /// - 0x28-0x33: fw_date (12 bytes, null-terminated)
    pub fn parse_firmware_info(&mut self, data: &[u8]) {
        if data.len() >= 64 {
            // Check magic - if 0xFFFFFFFF, firmware info is invalid
            let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0xFF; 4]));
            if magic != 0xFFFFFFFF {
                self.fw_version = extract_string(data, 0x1C, 0x28);
                self.fw_date = extract_string(data, 0x28, 0x34);
            }
        }
    }

    /// Parse CalibrationData block (64 bytes from 0x3000C00)
    ///
    /// Layout:
    /// - 0x00-0x06: serial_id (7 bytes, space-padded)
    /// - 0x07-0x26: UUID (32 bytes hex string)
    pub fn parse_calibration(&mut self, data: &[u8]) {
        if data.len() >= 64 {
            self.serial_id = extract_string(data, 0x00, 0x07).trim().to_string();
            self.uuid = extract_string(data, 0x07, 0x27);
        }
    }
}

/// Extract null-terminated string from byte slice
fn extract_string(data: &[u8], start: usize, end: usize) -> String {
    if start >= data.len() || end > data.len() || start >= end {
        return String::new();
    }
    let slice = &data[start..end];
    // Find null terminator or end of slice
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..len]).to_string()
}

/// Result of StreamingAuth command
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingAuthResult {
    /// Whether authentication was successful (AdcQueue access granted)
    pub success: bool,
    /// Raw attribute value from response
    pub attribute: u16,
    /// Auth level: 0 = failed, 1 = device auth, 2 = calibration auth
    pub auth_level: u8,
    /// Decrypted response payload (32 bytes)
    pub decrypted_payload: [u8; 32],
}

impl StreamingAuthResult {
    /// Check if AdcQueue streaming is enabled
    pub fn adcqueue_enabled(&self) -> bool {
        // Bit 1 of attribute indicates AdcQueue access
        (self.attribute & 0x02) != 0
    }
}

/// Result of device initialization
#[derive(Debug, Clone)]
pub struct InitResult {
    /// Device information (model, versions, serial, etc.)
    pub device_info: DeviceInfo,
    /// Hardware ID used for authentication
    pub hardware_id: HardwareId,
    /// Authentication result
    pub auth: StreamingAuthResult,
}

impl InitResult {
    /// Check if device is ready for AdcQueue streaming
    pub fn is_authenticated(&self) -> bool {
        self.auth.success && self.auth.adcqueue_enabled()
    }
}

/// Build MemoryRead encrypted payload (32 bytes)
///
/// # Arguments
/// * `address` - Memory address to read from
/// * `size` - Number of bytes to read
///
/// # Returns
/// 32-byte AES-encrypted payload
pub fn build_memory_read_payload(address: u32, size: u32) -> [u8; 32] {
    // Build 32-byte plaintext
    let mut plaintext = [0xFFu8; 32];

    // Bytes 0-3: Address (little-endian)
    plaintext[0..4].copy_from_slice(&address.to_le_bytes());

    // Bytes 4-7: Size (little-endian)
    plaintext[4..8].copy_from_slice(&size.to_le_bytes());

    // Bytes 8-11: Magic (0xFFFFFFFF)
    plaintext[8..12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    // Bytes 12-15: CRC32 of bytes 0-11
    let crc = crc32fast::hash(&plaintext[0..12]);
    plaintext[12..16].copy_from_slice(&crc.to_le_bytes());

    // Bytes 16-31: Already 0xFF from initialization

    // Encrypt with AES-128-ECB
    aes_ecb_encrypt(&plaintext, MEMORY_READ_KEY)
}

/// Build a MemoryRead (0x44) request packet
///
/// # Arguments
/// * `address` - Memory address to read from
/// * `size` - Number of bytes to read
/// * `tid` - Transaction ID
///
/// # Returns
/// 36-byte packet: 4-byte header + 32-byte AES-encrypted payload
pub fn build_memory_read_packet(address: u32, size: u32, tid: u8) -> Vec<u8> {
    let ciphertext = build_memory_read_payload(address, size);

    // Build packet: header + encrypted payload
    let mut packet = Vec::with_capacity(36);
    packet.push(0x44); // Packet type: MemoryRead
    packet.push(tid); // Transaction ID
    packet.push(0x01); // Attribute low byte
    packet.push(0x01); // Attribute high byte (0x0101)
    packet.extend_from_slice(&ciphertext);

    packet
}

/// Build StreamingAuth encrypted payload (32 bytes)
///
/// # Arguments
/// * `hardware_id` - 12-byte HardwareID from device
///
/// # Returns
/// 32-byte AES-encrypted payload
pub fn build_streaming_auth_payload(hardware_id: &HardwareId) -> [u8; 32] {
    // Build 32-byte plaintext
    let mut plaintext = [0u8; 32];

    // Bytes 0-7: Timestamp (milliseconds since epoch)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    plaintext[0..8].copy_from_slice(&timestamp.to_le_bytes());

    // Bytes 8-19: HardwareID (12 bytes) - THIS IS THE CRITICAL PART
    plaintext[8..20].copy_from_slice(hardware_id.as_bytes());

    // Bytes 20-31: Random padding
    let random_bytes: [u8; 12] = rand::random();
    plaintext[20..32].copy_from_slice(&random_bytes);

    // Encrypt with AES-128-ECB
    aes_ecb_encrypt(&plaintext, STREAMING_AUTH_KEY_ENC)
}

/// Encrypt a StreamingAuth payload (for serializing responses)
///
/// # Arguments
/// * `plaintext` - 32-byte plaintext payload
///
/// # Returns
/// 32-byte AES-encrypted payload
pub fn encrypt_streaming_auth_payload(plaintext: &[u8; 32]) -> [u8; 32] {
    aes_ecb_encrypt(plaintext, STREAMING_AUTH_KEY_ENC)
}

/// Build a StreamingAuth (0x4C) request packet
///
/// # Arguments
/// * `hardware_id` - 12-byte HardwareID from device
/// * `tid` - Transaction ID
///
/// # Returns
/// 36-byte packet: 4-byte header + 32-byte AES-encrypted payload
pub fn build_streaming_auth_packet(hardware_id: &HardwareId, tid: u8) -> Vec<u8> {
    let ciphertext = build_streaming_auth_payload(hardware_id);

    // Build packet: header + encrypted payload
    let mut packet = Vec::with_capacity(36);
    packet.push(0x4C); // Packet type: StreamingAuth
    packet.push(tid); // Transaction ID
    packet.push(0x00); // Attribute low byte
    packet.push(0x02); // Attribute high byte (0x0002)
    packet.extend_from_slice(&ciphertext);

    packet
}

/// Parse StreamingAuth (0x4C) response from full packet
///
/// # Arguments
/// * `response` - Raw response bytes (at least 36 bytes: 4-byte header + 32-byte payload)
///
/// # Returns
/// Parsed authentication result
pub fn parse_streaming_auth_response(response: &[u8]) -> Option<StreamingAuthResult> {
    if response.len() < 36 {
        return None;
    }

    // Check packet type (lower 7 bits)
    let packet_type = response[0] & 0x7F;
    if packet_type != 0x4C {
        return None;
    }

    // Get attribute (bytes 2-3, little-endian)
    let attribute = u16::from_le_bytes([response[2], response[3]]);

    // Decrypt payload (bytes 4-35)
    let encrypted = &response[4..36];
    let decrypted = aes_ecb_decrypt(encrypted.try_into().ok()?, STREAMING_AUTH_KEY_DEC);

    // Determine auth level from attribute
    // 0x0201 = auth failed, 0x0203 = auth success (level 1)
    let success = (attribute & 0x02) != 0;
    let auth_level = if success { 1 } else { 0 };

    Some(StreamingAuthResult {
        success,
        attribute,
        auth_level,
        decrypted_payload: decrypted,
    })
}

/// Parse StreamingAuth response from payload only (for use by message.rs)
///
/// # Arguments
/// * `payload` - Encrypted payload bytes (32 bytes)
///
/// # Returns
/// Parsed authentication result (attribute defaults to 0x0203 for success detection)
pub fn parse_streaming_auth_response_payload(payload: &[u8]) -> Option<StreamingAuthResult> {
    if payload.len() < 32 {
        return None;
    }

    let encrypted: [u8; 32] = payload[..32].try_into().ok()?;
    let decrypted = aes_ecb_decrypt(&encrypted, STREAMING_AUTH_KEY_DEC);

    // Without header, we can't determine attribute - assume success based on decryption
    // The caller should check the header's attribute field separately
    Some(StreamingAuthResult {
        success: true, // Caller should verify from header attribute
        attribute: 0x0203,
        auth_level: 1,
        decrypted_payload: decrypted,
    })
}

/// AES-128-ECB encrypt 32 bytes
fn aes_ecb_encrypt(plaintext: &[u8; 32], key: &[u8; 16]) -> [u8; 32] {
    let cipher = Aes128::new(key.into());

    let mut output = *plaintext;

    // Process two 16-byte blocks
    let (block1, block2) = output.split_at_mut(16);
    cipher.encrypt_block(block1.into());
    cipher.encrypt_block(block2.into());

    output
}

/// Decrypt MemoryRead response payload (e.g., HardwareID at 0x75)
///
/// The response payload is AES-encrypted with MEMORY_READ_KEY
pub fn decrypt_memory_read_response(ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 {
        return None;
    }

    // Decrypt in 16-byte blocks
    let cipher = Aes128::new(MEMORY_READ_KEY.into());
    let mut output = ciphertext.to_vec();

    for chunk in output.chunks_mut(16) {
        if chunk.len() == 16 {
            cipher.decrypt_block(chunk.into());
        }
    }

    Some(output)
}

/// AES-128-ECB decrypt 32 bytes
fn aes_ecb_decrypt(ciphertext: &[u8; 32], key: &[u8; 16]) -> [u8; 32] {
    let cipher = Aes128::new(key.into());

    let mut output = *ciphertext;

    // Process two 16-byte blocks
    let (block1, block2) = output.split_at_mut(16);
    cipher.decrypt_block(block1.into());
    cipher.decrypt_block(block2.into());

    output
}

/// AES-128-ECB decrypt a single 16-byte block
pub fn aes_ecb_decrypt_block(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut output = *ciphertext;
    cipher.decrypt_block((&mut output).into());
    output
}

/// AES-128-ECB decrypt multiple 16-byte blocks
///
/// # Arguments
/// * `ciphertext` - Encrypted data (must be multiple of 16 bytes)
/// * `key` - 16-byte AES key
///
/// # Returns
/// Decrypted data as Vec<u8>
pub fn aes_ecb_decrypt_blocks(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        ciphertext.len().is_multiple_of(16),
        "ciphertext must be multiple of 16 bytes"
    );

    let cipher = Aes128::new(key.into());
    let mut output = ciphertext.to_vec();

    for chunk in output.chunks_mut(16) {
        cipher.decrypt_block(chunk.into());
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known working hardcoded packets from CLI (captured from working session)
    // MemoryRead packet (tid=2): reads HardwareID from 0x40010450
    const HARDCODED_MEMORY_READ: &str = "4402010133f8860c0054288cdc7e52729826872dd18b539a39c407d5c063d91102e36a9e";
    // StreamingAuth packet (tid=6): authenticates with embedded HardwareID
    const HARDCODED_STREAMING_AUTH: &str = "4c0600025538815b69a452c83e54ef1d70f3bc9ae6aac1b12a6ac07c20fde58c7bf517ca";

    #[test]
    fn test_hardware_id_parsing() {
        // Example HardwareID: "071KBP" + separator + device ID 2577
        let bytes: [u8; 12] = [
            0x30, 0x37, 0x31, 0x4b, 0x42, 0x50, // "071KBP"
            0x0d, 0xff, // separator
            0x11, 0x0a, // device ID 2577 (LE)
            0xff, 0xff, // padding
        ];

        let hw_id = HardwareId::from_bytes(bytes);
        assert_eq!(hw_id.serial_prefix(), Some("071KBP".to_string()));
        assert_eq!(hw_id.device_id(), 2577);
    }

    #[test]
    fn test_aes_roundtrip() {
        let plaintext = [0x42u8; 32];
        let encrypted = aes_ecb_encrypt(&plaintext, STREAMING_AUTH_KEY_ENC);
        // Note: Can't decrypt with same key in real protocol, but can test structure
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted.len(), 32);
    }

    #[test]
    fn test_memory_read_packet_structure() {
        let packet = build_memory_read_packet(HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE as u32, 0x02);
        assert_eq!(packet.len(), 36);
        assert_eq!(packet[0], 0x44); // MemoryRead
        assert_eq!(packet[1], 0x02); // TID
        assert_eq!(packet[2], 0x01); // Attribute low
        assert_eq!(packet[3], 0x01); // Attribute high
    }

    #[test]
    fn test_streaming_auth_packet_structure() {
        let hw_id = HardwareId::from_bytes([0x30, 0x37, 0x31, 0x4b, 0x42, 0x50, 0x0d, 0xff, 0x11, 0x0a, 0xff, 0xff]);
        let packet = build_streaming_auth_packet(&hw_id, 0x06);
        assert_eq!(packet.len(), 36);
        assert_eq!(packet[0], 0x4C); // StreamingAuth
        assert_eq!(packet[1], 0x06); // TID
        assert_eq!(packet[2], 0x00); // Attribute low
        assert_eq!(packet[3], 0x02); // Attribute high (0x0002)
    }

    #[test]
    fn test_decrypt_hardcoded_memory_read() {
        // Decrypt the hardcoded MemoryRead packet to see what it reads
        // NOTE: The hardcoded packet reads from 0x420 (size 64), NOT 0x40010450 (HardwareID)
        let packet = hex::decode(HARDCODED_MEMORY_READ).unwrap();

        // Check header
        assert_eq!(packet[0], 0x44, "MemoryRead type");
        assert_eq!(packet[1], 0x02, "TID=2");
        assert_eq!(packet[2], 0x01, "Attribute low");
        assert_eq!(packet[3], 0x01, "Attribute high");

        // Decrypt payload (bytes 4-35)
        let ciphertext: [u8; 32] = packet[4..36].try_into().unwrap();
        let plaintext = aes_ecb_decrypt(&ciphertext, MEMORY_READ_KEY);

        // Extract address (bytes 0-3, little-endian)
        let address = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        // Extract size (bytes 4-7, little-endian)
        let size = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

        println!("Decrypted MemoryRead: address=0x{:08X}, size={}", address, size);
        println!("Plaintext: {:02x?}", plaintext);

        // The hardcoded packet actually reads from 0x420 with size 64 (different memory region)
        assert_eq!(address, 0x420, "Hardcoded reads from 0x420");
        assert_eq!(size, 64, "Hardcoded reads 64 bytes");
    }

    #[test]
    fn test_memory_read_for_hardware_id() {
        // Verify our library generates correct MemoryRead for HardwareID
        let generated = build_memory_read_packet(HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE as u32, 0x02);

        // Check header
        assert_eq!(generated[0], 0x44, "MemoryRead type");
        assert_eq!(generated[1], 0x02, "TID=2");
        assert_eq!(generated[2], 0x01, "Attribute low");
        assert_eq!(generated[3], 0x01, "Attribute high");

        // Decrypt and verify address/size
        let ciphertext: [u8; 32] = generated[4..36].try_into().unwrap();
        let plaintext = aes_ecb_decrypt(&ciphertext, MEMORY_READ_KEY);

        let address = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let size = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

        assert_eq!(address, HARDWARE_ID_ADDRESS, "Should read from 0x40010450");
        assert_eq!(size, HARDWARE_ID_SIZE as u32, "Should read 12 bytes");

        // Verify CRC32 is correct (bytes 12-15)
        let expected_crc = crc32fast::hash(&plaintext[0..12]);
        let actual_crc = u32::from_le_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);
        assert_eq!(actual_crc, expected_crc, "CRC32 should be valid");
    }

    #[test]
    fn test_decrypt_hardcoded_streaming_auth() {
        // Decrypt the hardcoded StreamingAuth packet to extract HardwareID
        let packet = hex::decode(HARDCODED_STREAMING_AUTH).unwrap();

        // Check header
        assert_eq!(packet[0], 0x4C, "StreamingAuth type");
        assert_eq!(packet[1], 0x06, "TID=6");
        assert_eq!(packet[2], 0x00, "Attribute low");
        assert_eq!(packet[3], 0x02, "Attribute high");

        // Decrypt payload (bytes 4-35) using ENCRYPT key (since host->device uses encrypt key)
        let ciphertext: [u8; 32] = packet[4..36].try_into().unwrap();
        let plaintext = aes_ecb_decrypt(&ciphertext, STREAMING_AUTH_KEY_ENC);

        // Structure: timestamp(8) + HardwareID(12) + padding(12)
        let timestamp = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
        let hardware_id_bytes: [u8; 12] = plaintext[8..20].try_into().unwrap();
        let hardware_id = HardwareId::from_bytes(hardware_id_bytes);

        println!("Decrypted StreamingAuth:");
        println!("  Timestamp: {} ms", timestamp);
        println!("  HardwareID: {}", hardware_id);
        println!("  Serial prefix: {:?}", hardware_id.serial_prefix());
        println!("  Device ID: {}", hardware_id.device_id());
        println!("  Plaintext: {:02x?}", plaintext);

        // Verify the extracted HardwareID
        assert_eq!(hardware_id.serial_prefix(), Some("071KBP".to_string()));
        assert_eq!(hardware_id.device_id(), 2577);
        assert!(timestamp > 0, "Timestamp should be non-zero");
    }

    #[test]
    fn test_streaming_auth_with_known_hardware_id() {
        // Use the HardwareID extracted from the working hardcoded packet
        // HardwareID: 071KBP, device ID 2577
        let hw_id = HardwareId::from_bytes([
            0x30, 0x37, 0x31, 0x4b, 0x42, 0x50, // "071KBP"
            0x0d, 0xff, // separator
            0x11, 0x0a, // device ID 2577 (LE)
            0xff, 0xff, // padding
        ]);

        // Generate StreamingAuth packet
        let packet = build_streaming_auth_packet(&hw_id, 0x06);

        // Verify header matches hardcoded
        let hardcoded = hex::decode(HARDCODED_STREAMING_AUTH).unwrap();
        assert_eq!(&packet[0..4], &hardcoded[0..4], "Headers must match");

        // Decrypt our generated packet to verify HardwareID is embedded correctly
        let ciphertext: [u8; 32] = packet[4..36].try_into().unwrap();
        let plaintext = aes_ecb_decrypt(&ciphertext, STREAMING_AUTH_KEY_ENC);

        // Extract and verify HardwareID
        let extracted_hw: [u8; 12] = plaintext[8..20].try_into().unwrap();
        assert_eq!(extracted_hw, hw_id.bytes, "HardwareID must be embedded correctly");

        // Timestamp should be recent (within last hour - 3600000 ms)
        let timestamp = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(timestamp > now - 3600000, "Timestamp should be recent");
        assert!(timestamp <= now + 1000, "Timestamp should not be in future");
    }
}
