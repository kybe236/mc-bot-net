pub fn read_boolean(buffer: &[u8], offset: Option<&mut usize>) -> Option<bool> {
    let mut binding = 0;
    let offset = offset.unwrap_or(&mut binding);

    if buffer.len() < *offset + 1 {
        return None;
    }

    let byte = buffer[*offset];
    *offset += 1;

    Some(byte == 0x01)
}

#[allow(unused)]
pub fn write_boolean(buffer: &mut Vec<u8>, value: bool) {
    buffer.push(if value { 0x01 } else { 0x00 });
}
