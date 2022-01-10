mod cipher;
mod common;
mod constants;
mod helpers;
mod inverse;
mod math;
use crate::cipher::Cipher;
use crate::inverse::InvCipher;



fn encode(input: Vec<u8>) -> Vec<u8>{
    let K: Vec<u32> = Vec::new();   // the cipher key    
    Cipher(&input)
}

fn decode(input: Vec<u8>) -> Vec<u8> {
    let K: Vec<u32> = Vec::new();
    InvCipher(&input)
}

/// Main Function
fn main() {
    let v = encode(vec![0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70]);
    //println!("{}", FiniteMult(0x57,0x83));
}









////////////////////////// TESTS BELOW //////////////////////

#[cfg(test)]
mod tests {
    use crate::common::KeyExpansion;
    use crate::constants::Nb;
    use crate::helpers::GenerateRoundConstant;
    use crate::math::{FiniteMult, xtime, FiniteAdd};

    use crate::{encode, decode};

    use rand::RngCore;
    use rand::rngs::OsRng;
    

    #[test]
    fn test_add() {
        assert_eq!(FiniteAdd(0x57, 0x83), 0xd4);
    }

    

    #[test]
    fn test_mult() {
        assert_eq!(FiniteMult(0x57, 0x13), 0xfe);
        assert_eq!(FiniteMult(0x57, 0x83), 0xc1);
    }

    #[test]
    fn test_xtime(){
        assert_eq!(xtime(0x57), 0xae);
        assert_eq!(xtime(0xae), 0x47);
        assert_eq!(xtime(0x47), 0x8e);
        assert_eq!(xtime(0x8e), 0x07);
    }

    #[test]
    fn test_expansion(){
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut w: Vec<u32> = vec![0; Nb as usize];
        let Rcon = GenerateRoundConstant();
        KeyExpansion(key.to_vec(), &mut w, Rcon);
        assert_eq!(w,vec![0x2b7e1516u32, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]);
    }


    #[test]
    fn test_cipher() {
        let mut rbytes = [0u8; 16];
            
        for _ in 0..1024 {
            OsRng.fill_bytes(&mut rbytes);
            assert_eq!(decode(encode(rbytes.to_vec())), rbytes);
        }
    }
}