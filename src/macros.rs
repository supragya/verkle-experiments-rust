#![macro_use]

// Not thread safe
pub static mut track_offset: u8 = 0;
// #[macro_export]
macro_rules! track {
    ($name:expr, $expression:expr) => {{
        use crate::macros::track_offset;
        use std::time::Instant;
        let now = Instant::now();
        let mut offset = "".to_string();
        let tkoff: u8;
        unsafe {
            tkoff = track_offset;
            track_offset += 1;
        }
        for _ in 0..tkoff {
            offset = offset + "  ";
        }
        println!("{}+[{}]", offset, $name);
        let tmp = $expression;
        unsafe {
            track_offset -= 1;
        }
        let elapsed = now.elapsed();
        println!("{}-[{}], elapsed {:.2?}", offset, $name, elapsed);
        tmp
    }};
}
pub(crate) fn convert_to_arr<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

macro_rules! makeu8_32 {
    ($string:expr) => {{
        let hexlen_to_pad = 64 - $string.len();
        let mut tmpstring: String = $string.to_string();
        for _ in 0..hexlen_to_pad {
            tmpstring = tmpstring + "0"
        }
        crate::macros::convert_to_arr(hex::decode(tmpstring).unwrap())
    }};
}
