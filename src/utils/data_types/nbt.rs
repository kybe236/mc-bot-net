use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NbtValue {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    ByteArray(Vec<u8>),
    String(String),
    List(Vec<NbtValue>),
    Compound(HashMap<String, NbtValue>),
    IntArray(Vec<i32>),
    LongArray(Vec<i64>),
    End,
}

impl Display for NbtValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NbtValue::Byte(b) => write!(f, "{}", b),
            NbtValue::Short(s) => write!(f, "{}", s),
            NbtValue::Int(i) => write!(f, "{}", i),
            NbtValue::Long(l) => write!(f, "{}", l),
            NbtValue::Float(float) => write!(f, "{}", float),
            NbtValue::Double(d) => write!(f, "{}", d),
            NbtValue::ByteArray(arr) => write!(f, "{:?}", arr),
            NbtValue::String(s) => write!(f, "{}", s),
            NbtValue::List(lst) => {
                let list_str: Vec<String> = lst.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", list_str.join(", "))
            }
            NbtValue::Compound(map) => {
                let map_str: Vec<String> = map
                    .iter()
                    .map(|(key, value)| format!("{}: {}", key, value))
                    .collect();
                write!(f, "{{{}}}", map_str.join(", "))
            }
            NbtValue::IntArray(arr) => write!(f, "{:?}", arr),
            NbtValue::LongArray(arr) => write!(f, "{:?}", arr),
            NbtValue::End => write!(f, "TAG_End"),
        }
    }
}

impl NbtValue {
    #[allow(unused)]
    pub fn parse(data: &[u8], index: &mut usize) -> Result<NbtValue, String> {
        let tag_id = NbtValue::read_byte(data, index).unwrap() as u8;

        NbtValue::parse_value(tag_id, data, index)
    }

    #[allow(unused)]
    fn read_byte(data: &[u8], index: &mut usize) -> Result<i8, String> {
        if *index >= data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = data[*index] as i8;
        *index += 1; // Increment the index after reading the byte
        Ok(value)
    }

    #[allow(unused)]
    fn read_short(data: &[u8], index: &mut usize) -> Result<i16, String> {
        if *index + 2 > data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = i16::from_be_bytes(data[*index..*index + 2].try_into().unwrap());
        *index += 2; // Increment the index after reading the short
        Ok(value)
    }

    #[allow(unused)]
    fn read_int(data: &[u8], index: &mut usize) -> Result<i32, String> {
        if *index + 4 > data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = i32::from_be_bytes(data[*index..*index + 4].try_into().unwrap());
        *index += 4; // Increment the index after reading the int
        Ok(value)
    }

    #[allow(unused)]
    fn read_long(data: &[u8], index: &mut usize) -> Result<i64, String> {
        if *index + 8 > data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = i64::from_be_bytes(data[*index..*index + 8].try_into().unwrap());
        *index += 8; // Increment the index after reading the long
        Ok(value)
    }

    #[allow(unused)]
    fn read_float(data: &[u8], index: &mut usize) -> Result<f32, String> {
        if *index + 4 > data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = f32::from_be_bytes(data[*index..*index + 4].try_into().unwrap());
        *index += 4; // Increment the index after reading the float
        Ok(value)
    }

    #[allow(unused)]
    fn read_double(data: &[u8], index: &mut usize) -> Result<f64, String> {
        if *index + 8 > data.len() {
            return Err("Out of bounds".to_string());
        }

        let value = f64::from_be_bytes(data[*index..*index + 8].try_into().unwrap());
        *index += 8; // Increment the index after reading the double
        Ok(value)
    }

    #[allow(unused)]
    fn read_byte_array(data: &[u8], index: &mut usize) -> Result<Vec<u8>, String> {
        let length = NbtValue::read_int(data, index)? as usize;
        let value = data[*index..*index + length].to_vec();
        *index += length; // Increment the index after reading the byte array
        Ok(value)
    }

    #[allow(unused)]
    fn read_tag_list(data: &[u8], index: &mut usize) -> Result<Vec<NbtValue>, String> {
        let tag_id = NbtValue::read_byte(data, index)? as u8;
        let length = NbtValue::read_int(data, index)? as usize;
        let mut list = Vec::with_capacity(length);
        for _ in 0..length {
            list.push(NbtValue::parse_value(tag_id, data, index)?);
        }
        Ok(list)
    }

    #[allow(unused)]
    fn read_int_array(data: &[u8], index: &mut usize) -> Result<Vec<i32>, String> {
        let length = NbtValue::read_int(data, index)? as usize;
        let mut array = Vec::with_capacity(length);
        for _ in 0..length {
            array.push(NbtValue::read_int(data, index)?);
        }
        Ok(array)
    }

    #[allow(unused)]
    fn read_long_array(data: &[u8], index: &mut usize) -> Result<Vec<i64>, String> {
        let length = NbtValue::read_int(data, index)? as usize;
        let mut array = Vec::with_capacity(length);
        for _ in 0..length {
            array.push(NbtValue::read_long(data, index)?);
        }
        Ok(array)
    }

    #[allow(unused)]
    fn read_string(data: &[u8], index: &mut usize) -> Result<String, String> {
        let length = NbtValue::read_short(data, index)? as usize;
        let value = String::from_utf8(data[*index..*index + length].to_vec())
            .map_err(|_| "Invalid UTF-8".to_string())?;
        *index += length; // Increment the index after reading the string
        Ok(value)
    }

    #[allow(unused)]
    fn parse_value(tag_id: u8, data: &[u8], index: &mut usize) -> Result<NbtValue, String> {
        match tag_id {
            0 => Ok(NbtValue::End),
            1 => Ok(NbtValue::Byte(NbtValue::read_byte(data, index)?)),
            2 => Ok(NbtValue::Short(NbtValue::read_short(data, index)?)),
            3 => Ok(NbtValue::Int(NbtValue::read_int(data, index)?)),
            4 => Ok(NbtValue::Long(NbtValue::read_long(data, index)?)),
            5 => Ok(NbtValue::Float(NbtValue::read_float(data, index)?)),
            6 => Ok(NbtValue::Double(NbtValue::read_double(data, index)?)),
            7 => Ok(NbtValue::ByteArray(NbtValue::read_byte_array(data, index)?)),
            8 => Ok(NbtValue::String(NbtValue::read_string(data, index)?)),
            9 => Ok(NbtValue::List(NbtValue::read_tag_list(data, index)?)),
            10 => Ok(NbtValue::Compound(NbtValue::parse_compound(
                data, index, false,
            )?)),
            11 => Ok(NbtValue::IntArray(NbtValue::read_int_array(data, index)?)),
            12 => Ok(NbtValue::LongArray(NbtValue::read_long_array(data, index)?)),
            _ => Err(format!("Unknown tag ID: {}", tag_id)),
        }
    }

    fn parse_compound(
        data: &[u8],
        index: &mut usize,
        root: bool,
    ) -> Result<HashMap<String, NbtValue>, String> {
        let mut map: HashMap<String, NbtValue> = HashMap::new();
        let mut first = true;
        loop {
            let tag_id = NbtValue::read_byte(data, index).unwrap() as u8;
            if tag_id == 0 {
                break; // TAG_End
            }
            let name = if root && first {
                first = false;
                "".to_string()
            } else {
                NbtValue::read_string(data, index)?
            };
            let value = NbtValue::parse_value(tag_id, data, index).unwrap();

            if !name.is_empty() {
                // Insert only if the name is not empty
                map.insert(name, value);
            }
        }
        Ok(map)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn read_byte() {
        let data = vec![0x01];
        let mut index = 0;
        let value = NbtValue::read_byte(&data, &mut index).unwrap();
        assert_eq!(value, 1);
        assert_eq!(index, 1);
    }

    #[test]
    pub fn read_short() {
        let data = vec![0x00, 0x01];
        let mut index = 0;
        let value = NbtValue::read_short(&data, &mut index).unwrap();
        assert_eq!(value, 1);
        assert_eq!(index, 2);
    }

    #[test]
    pub fn read_int() {
        let data = vec![0x00, 0x00, 0x00, 0x01];
        let mut index = 0;
        let value = NbtValue::read_int(&data, &mut index).unwrap();
        assert_eq!(value, 1);
        assert_eq!(index, 4);
    }

    #[test]
    pub fn read_long() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut index = 0;
        let value = NbtValue::read_long(&data, &mut index).unwrap();
        assert_eq!(value, 1);
        assert_eq!(index, 8);
    }

    #[test]
    pub fn read_float() {
        let data = vec![0x3F, 0x80, 0x00, 0x00];
        let mut index = 0;
        let value = NbtValue::read_float(&data, &mut index).unwrap();
        assert_eq!(value, 1.0);
        assert_eq!(index, 4);
    }

    #[test]
    pub fn read_double() {
        let data = vec![0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut index = 0;
        let value = NbtValue::read_double(&data, &mut index).unwrap();
        assert_eq!(value, 1.0);
        assert_eq!(index, 8);
    }

    #[test]
    pub fn read_string() {
        let data = vec![0x00, 0x04, 0x74, 0x65, 0x73, 0x74];
        let mut index = 0;
        let value = NbtValue::read_string(&data, &mut index).unwrap();
        assert_eq!(value, "test");
        assert_eq!(index, 6);
    }

    #[test]
    pub fn read_byte_array() {
        let data = vec![0x00, 0x00, 0x00, 0x01, 0x01];
        let mut index = 0;
        let value: Vec<u8> = NbtValue::read_byte_array(&data, &mut index).unwrap();
        assert_eq!(value, vec![1]);
        assert_eq!(index, 5);
    }

    #[test]
    pub fn read_int_array() {
        let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let mut index = 0;
        let value = NbtValue::read_int_array(&data, &mut index).unwrap();
        assert_eq!(value, vec![1]);
        assert_eq!(index, 8);
    }

    #[test]
    pub fn read_long_array() {
        let data = vec![
            0x00, 0x00, 0x00, 0x02, // Length of the array (2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // First long (1)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Second long (-1)
        ];
        let mut index = 0;
        let value = NbtValue::read_long_array(&data, &mut index).unwrap();
        assert_eq!(value, vec![1, -1]);
        assert_eq!(index, 20);
    }

    #[test]
    pub fn read_tag_list() {
        let data = vec![
            0x03, // Tag type (int)
            0x00, 0x00, 0x00, 0x02, // Length of the list (2)
            0x00, 0x00, 0x00, 0x01, // First element (1)
            0x00, 0x00, 0x00, 0x02, // Second element (2)
        ];
        let mut index = 0;
        let value = NbtValue::read_tag_list(&data, &mut index).unwrap();
        assert_eq!(value, vec![
            super::NbtValue::Int(1),
            super::NbtValue::Int(2)
        ]);
        assert_eq!(index, 13);
    }

    #[test]
    pub fn read_component() {
        let data = vec![
            0x01, //byte
            0x00, 0x04, 0x74, 0x65, 0x73, 0x74, //string lenght
            0x00, //value
            0x00, //tag end
        ];
        let mut index = 0;
        let value = NbtValue::parse_compound(&data, &mut index, false).unwrap();

        let byte = value.get("test").unwrap();
        assert_eq!(byte, &NbtValue::Byte(0));
    }

    #[test]
    pub fn test_parse() {
        let data = vec![
            0x0A, // TAG_Compound
            0x02, // TAG_Short
            0x00, 0x01, 0x72, // Name: "r"
            0x00, 0x01, // Value: 1
            0x00, // TAG_End
        ];

        let result = NbtValue::parse(&data, &mut 0);
        assert!(result.is_ok());
        let nbt = result.unwrap();

        assert_eq!(
            nbt,
            NbtValue::Compound(
                vec![("r".to_string(), NbtValue::Short(1),)]
                    .into_iter()
                    .collect()
            )
        );
    }
}
