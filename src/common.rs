use crate::constants::*;
use crate::helpers::*;
use crate::math::*;


/// "Tranformation in the Cipher and Inverse Cipher in which
/// a Round Key is added to the State using an XOR operation.
/// The length of a Round Key equals the size of the STATE
/// (i.e. for Nb=4, the Round Key length equals 128bit/16Byte)
pub fn AddRoundKey(state: &mut Vec<Vec<u8>>, roundkey: Vec<u8>) {
    // add the round key to each column, with each column getting added
    // to each corresponding index of roundkey
    
    // note: we know the state is 16x16
    for column in 0..16{
        for row in 0..state.len(){
            state[row][column] = FiniteAdd(state[row][column], roundkey[column]);
        }
    }
}

/// Expands the key for use in the algorithm
pub fn KeyExpansion(key: Vec<u8>, w: &mut Vec<u32>, Rcon: Vec<u8>){
    
    // populate the key schedule 
    for i in 0..Nk {
        w[i as usize] = MakeWord(key[(4*i) as usize], key[(4*i+1) as usize], key[(4*i+2) as usize], key[(4*i+3) as usize]);
    }

    for i in Nk..(Nb * (Nr+1)){
        let mut tmp = MakeBytes(w[(i-1) as usize]);
        if i % Nk == 0 {
            tmp = SubWord(RotWord(tmp));
            for v in 0..tmp.len() {
                tmp[v] ^= Rcon[(i/Nk) as usize];
            }
        } else if (Nk > 6) && (i % Nk == 4) {
            tmp = SubWord(tmp);
        }
        w[i as usize] = w[(i-Nk) as usize] ^ MakeWord(tmp[0], tmp[1],tmp[2],tmp[3]);
    }
}


/// Used in the Key Expansion routine that takes a 4-byte word
/// and performs a cyclic permutation
pub fn RotWord(word: [u8;4]) -> [u8;4] {
    [0u8;4]
}

/// Used in the Key Expansion routine that takes 4-byte
/// input word and applies an S-box to each of the four
/// bytes to produce an output word.
pub fn SubWord(word: [u8;4]) -> [u8;4] {
    [0u8;4]
}
