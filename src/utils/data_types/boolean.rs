pub fn read_boolean(buffer: &[u8], offset: Option<&mut usize>) -> bool {
    let mut binding = 0;
    let offset = offset.unwrap_or(&mut binding);

    // Ensure the buffer has enough data (at least 1 byte)
    if buffer.len() < *offset + 1 {
        panic!("Insufficient data to read a boolean");
    }

    // Read the boolean as a byte (0x01 for true, 0x00 for false)
    let byte = buffer[*offset];

    // Increment the offset by 1 since we are reading 1 byte
    *offset += 1;

    // Return true if byte is 0x01, false if byte is 0x00
    byte == 0x01
}

#[allow(unused)]
pub fn write_boolean(buffer: &mut Vec<u8>, value: bool) {
    // Append 0x01 for true, 0x00 for false
    buffer.push(if value { 0x01 } else { 0x00 });
}
