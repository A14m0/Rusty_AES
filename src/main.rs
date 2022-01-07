use std::convert::TryInto;

// our fancy little lookup table, called the S-box
const sbox: [[u8;16];16] = [[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
    [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
    [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
    [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
    [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
    [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
    [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
    [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
    [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
    [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
    [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
    [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
    [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
    [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
    [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
    [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]];

/// The number of 32-bit words in 128 bits
const Nb: u32 = 4;
/// Number of 32-bit words comprising the Cipher Key
const Nk: u32 = 4;       
/// Number or rounds, function of Nk and Nb
const Nr: u32  = 10;       


/// Helper function that places the input in a proper state array
fn CopyToState(input: Vec<u8>) -> Vec<Vec<u8>> {
    let mut state: Vec<Vec<u8>> = vec![vec![0;Nb as usize]; 4];
    for row in 0..4 {
        for col in 0..Nb as usize {
            state[row][col] = input[row + 4*col];
        }
    }
    state
} 

/// Helper function that converts a state to an output vector
fn ToOutput(state: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; 128];

    for row in 0..4usize {
        for col in 0..(Nb as usize) {
            out[4*col + row] = state[row][col];
        }
    }
    out
}

/// Helper function that converts 4 bytes into a 32-bit word
fn MakeWord(a: u8, b: u8, c: u8, d: u8) -> u32 {
    let mut o = 0;
    o = (a as u32) << 24;
    o += (b as u32) << 16;
    o += (c as u32) << 8;
    o += d as u32;

    o
}

/// Helper function that converts a word to 4 bytes
fn MakeBytes(a: u32) -> [u8; 4] {
    let mut o = [0u8; 4];
    o[3] = (a & 0xff).try_into().unwrap();
    o[2] = ((a >> 8) & 0xff).try_into().unwrap();
    o[1] = ((a >> 16) & 0xff).try_into().unwrap();
    o[0] = ((a >> 24) & 0xff).try_into().unwrap();
    
    o
}

/// Helper function to add finite field elements together
/// which is used throughout the cipher
fn FiniteAdd(a: u8, b: u8) -> u8{
    a ^ b
}

/// Helper function to multiply finite field elements
/// together, which is used throught the cipher. Used 
/// in FiniteMult function
fn xtime(a: u8) -> u8 {
    let mut ret= a as u16;
    ret = ret << 1;

    if a & (0x80) != 0 { // see if the highest bit is set (b7)
        ret ^= 0x1b;
        ret &= 0xff; // keep it in byte range
    }

    ret as u8
}

/// Helper function to multiply finite field elements
/// together, which is used throught the cipher
fn FiniteMult(a: u8, b: u8) -> u8 {
    let mut total = 0;
    // what we can do is look at the bits values in b
    // and use them as equivilent to each position
    // i.e. for 0x13 --> 10011 --> 0x01+0x02+0x10
    for i in 0..8u32{
        let bit = b & (1<<i);
        let mut xtime_val = a;
        let mut tmp = 1;
        
        // get the correct xtime_value for the target bit and add it
        if bit != 0 {
            while tmp < bit{
                xtime_val = xtime(xtime_val);
                tmp = tmp << 1;
            }
            total = FiniteAdd(total, xtime_val);
        }
        
    }

    total
}


/// "Tranformation in the Cipher and Inverse Cipher in which
/// a Round Key is added to the State using an XOR operation.
/// The length of a Round Key equals the size of the STATE
/// (i.e. for Nb=4, the Round Key length equals 128bit/16Byte)
fn AddRoundKey(state: &mut Vec<Vec<u8>>, roundkey: Vec<u8>) {
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
fn KeyExpansion(key: Vec<u8>, w: &mut Vec<u32>, Rcon: Vec<u8>){
    
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

/// Transformation in the Inverse Cipher that is the inverse
/// of MixColumns
fn InvMixColumns(state: &mut Vec<Vec<u8>>) {
}

/// Transformation in the Inverse Cipher that is the inverse
/// of ShiftRows
fn InvShiftRows(state: &mut Vec<Vec<u8>>) {
    // shift each row by its column index
    for row in 0..16 {
        let mut tmp_arr: Vec<u8> = vec![0; Nk as usize];
        let mut idx = 16-row;
        for col in 0..16{ 
            if idx == 16 {idx = 0}
            tmp_arr[idx] = state[row][col]; // get the value at index+offset, looping
            idx += 1;
        }
        // copy the data from the temporary array back into state
        for col in 0..16 {
            state[row][col] = tmp_arr[col];
        }
    }
}

/// Transformation in the Inverse Cipher that is the inverse
/// of SubBytes
fn InvSubBytes(state: &mut Vec<Vec<u8>>) {
}

/// Transformation in the Cipher that takes all of the columns
/// of the State and mixes their data (independently of eachother)
/// to produce new columns
fn MixColumns(state: &mut Vec<Vec<u8>>) {
    let matrix = [[2,3,1,1],
                  [1,2,3,1],
                  [1,1,2,3],
                  [3,1,1,2]];

    for column in 0..16 {
        for row in 0..16 {
            let t1 = state[0][column];
            let t2 = state[1][column];
            let t3 = state[2][column];
            let t4 = state[3][column];

            state[row][column] = FiniteMult(t1, matrix[row][0]) ^
                                 FiniteMult(t2, matrix[row][1]) ^
                                 FiniteMult(t3, matrix[row][2]) ^
                                 FiniteMult(t4, matrix[row][3]);
        }
    }
}

/// Used in the Key Expansion routine that takes a 4-byte word
/// and performs a cyclic permutation
fn RotWord(word: [u8;4]) -> [u8;4] {
    [0u8;4]
}

/// Transformation in the Cipher that processes the State by
/// cyclically shifting the last three rows of the State by
/// different offsets
fn ShiftRows(state: &mut Vec<Vec<u8>>) {
    // shift each row by its column index
    for row in 0..16 {
        let mut tmp_arr: Vec<u8> = vec![0; 16];
        for col in 0..Nb{
            tmp_arr[col as usize] = state[row as usize][((col+row)%4)as usize] // get the value at index+offset, looping
        }
        // copy the data from the temporary array back into state
        for col in 0..16 {
            state[row as usize][col] = tmp_arr[col];
        }
    }
}

/// Transformation in the Cipher that processes the State
/// using a non-linear byte substitution table (S-box) that
/// operates on each of the State bytes independently
fn SubBytes(state: &mut Vec<Vec<u8>>) {
    // to transform a byte, we do this: 
    // say we had a value s(1,1) = 0x53
    // to compute the replaced value, we would go to 
    // sbox[0x5][0x3] and replace 0x53 with the byte 
    // at the index (which should be 0xed)

    // for each row...
    for row in 0..16 {
        // for each column
        for col in 0..16{
            // replace the byte with the byte in sbox[bit&0xf0][bit&0xf]
            let bit = state[row][col];
            let x = bit & 0xf0;
            let y = bit & 0xf;
            state[row][col] = sbox[x as usize][y as usize];
        }
    }
}

/// Used in the Key Expansion routine that takes 4-byte
/// input word and applies an S-box to each of the four
/// bytes to produce an output word.
fn SubWord(word: [u8;4]) -> [u8;4] {
    [0u8;4]
}

/// The function that actually encodes a block
/// Note in  -> vec<u8> [4 x Nb]
///      out -> vec<u8> [4 x Nb]
///      w   -> vec<u32> [Nb x (Nr+1)]
fn Cipher(input: &Vec<u8>, Rcon: Vec<u8>) -> Vec<u8>
{
    //let state:Vec<Vec<u8>> = vec![vec![0; 4]; Nb as usize];
    let mut state = CopyToState(input.clone());
    let mut w: Vec<u8> = vec![0; (Nb*(Nr+1)) as usize];
    
    AddRoundKey(&mut state, w[0..(Nb-1) as usize].to_vec()); // See Sec. 5.1.4
    let cap = Nr-1;
    for round in 1..cap {
        SubBytes(&mut state); // See Sec. 5.1.1
        ShiftRows(&mut state); // See Sec. 5.1.2
        MixColumns(&mut state); // See Sec. 5.1.3
        AddRoundKey(&mut state, w[(round*Nb) as usize..((round+1)*Nb-1) as usize].to_vec());//..((round+1)*Nb-1) as usize
    }
        
    
    SubBytes(&mut state);
    ShiftRows(&mut state);
    AddRoundKey(&mut state, w[(Nr*Nb) as usize..((Nr+1)*Nb-1) as usize].to_vec());//..((Nr+1)*Nb-1) as usize

    ToOutput(state)
}

/// The inverse of `Cipher`
fn InvCipher(input: &Vec<u8>, Rcon: Vec<u8>) -> Vec<u8> {
    let mut state = CopyToState(input.clone());
    let mut w: Vec<u8> = vec![0; (Nb*(Nr+1)) as usize];

    AddRoundKey(&mut state, w[(Nr*Nb) as usize..((Nr+1)*Nb-1) as usize].to_vec());
    for round in Nr-1..0 {
        InvShiftRows(&mut state);
        InvSubBytes(&mut state);
        AddRoundKey(&mut state, w[(round*Nb) as usize..((round+1)*Nb-1) as usize].to_vec());
        InvMixColumns(&mut state);
    }

    InvShiftRows(&mut state);
    InvSubBytes(&mut state);
    AddRoundKey(&mut state, w[0..(Nb-1) as usize].to_vec());

    ToOutput(state)
}

fn encode(input: Vec<u8>){
    let K: Vec<u32> = Vec::new();   // the cipher key    
    let Rcon: Vec<u8> = Vec::new();  // Round constant word array
    let out = Cipher(&input, Rcon);
}

/// Main Function
fn main() {
    
    println!("{}", FiniteMult(0x57,0x83));
}









////////////////////////// TESTS BELOW //////////////////////

#[cfg(test)]
mod tests {
    use crate::{FiniteMult, xtime, FiniteAdd, KeyExpansion, Nb};

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


    //#[test]
    //fn test_cipher() {
        //assert_eq!(Cipher(input, sbox, w, Nr, Nb))
    //}
}