// A trait for converting any type to and from a bit sequence, so it can
// be encrypted as a Vec<LWEBitCiphertext> (one ciphertext per bit) and
// decrypted back into the original type.

// Types implementing this can be encoded into a bitvector to be used
// for encryption and decryption.
pub trait BitCodec: Sized {
    //Encode type as a bitstring
    fn to_bits(&self) -> Vec<bool>;
    //Try to decode bitstring (if invalid bitstring returns Err)
    //Bits arg is NOT ensured to be correct, make sure to validate
    fn from_bits(bits: &[bool]) -> Result<Self, String>;
}

// Basic BitCodec Implementations //
/*
    [x] - u8, u16, u32, u64
    [x] - String
*/
macro_rules! impl_bitcodec_for_uint {
    ($t:ty, $bits:expr) => {
        impl BitCodec for $t {
            fn to_bits(&self) -> Vec<bool> {
                (0..$bits).rev().map(|i| (self >> i) & 1 == 1).collect()
            }
 
            fn from_bits(bits: &[bool]) -> Result<Self, String> {
                if bits.len() != $bits {
                    return Err(format!("Wrong bit length for {}", stringify!($t)));
                }
                Ok(bits.iter().fold(0 as $t, |acc, &b| (acc << 1) | (b as $t)))
            }
        }
    };
}

impl_bitcodec_for_uint!(u8, 8);
impl_bitcodec_for_uint!(u16, 16);
impl_bitcodec_for_uint!(u32, 32);
impl_bitcodec_for_uint!(u64, 64);

impl BitCodec for String {
    fn to_bits(&self) -> Vec<bool> {
        let byte_len = self.as_bytes().len() as u32;
        let mut bits = byte_len.to_bits(); //32-bit prefix
        for byte in self.as_bytes() {
            bits.extend(byte.to_bits()); //Most signifigant bits
        }
        bits
    }

    fn from_bits(bits: &[bool]) -> Result<Self, String> {
        if bits.len() < 32 {
            return Err(format!("Expected >=32-bit prefix, got {}", bits.len()));
        }
        let byte_len = u32::from_bits(&bits[0..32])? as usize;
        let exp_total = 32+byte_len*8;
        if bits.len() != exp_total {
            return Err(format!(
                "Length prefix says {} (expected total of {}), but got {} bits", 
                byte_len, exp_total, bits.len()));
        }
        let string_bits = &bits[32..];
        let bytes: Vec<u8> = string_bits.chunks(8).map(|s| u8::from_bits(s).unwrap()).collect();
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }
}