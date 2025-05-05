
pub fn read_uuid(buffer: &[u8], offset: Option<&mut usize>) -> u128 {
    let mut index = 0;
    let offset = offset.unwrap_or(&mut index);

    // Read the 16 bytes for the UUID (128 bits = 16 bytes)
    let uuid_bytes = &buffer[*offset..*offset + 16];

    // Update the offset
    *offset += 16;

    // Reverse the bytes if they're in little-endian order (to match big-endian UUID format)
    let mut reversed_uuid_bytes = uuid_bytes.to_vec();
    reversed_uuid_bytes.reverse();

    // Convert the reversed bytes into a u128 (UUID is 128 bits)
    u128::from_le_bytes(reversed_uuid_bytes.try_into().expect("Invalid UUID length"))
}

pub fn write_uuid(buffer: &mut Vec<u8>, uuid: u128) {
    // Split the UUID into two 64-bit parts
    let msb = (uuid >> 64) as u64; // Most significant 64 bits
    let lsb = uuid as u64; // Least significant 64 bits

    // Write the most significant bits (MSB) as 8 bytes (64 bits)
    buffer.extend_from_slice(&msb.to_be_bytes());

    // Write the least significant bits (LSB) as 8 bytes (64 bits)
    buffer.extend_from_slice(&lsb.to_be_bytes());
}
