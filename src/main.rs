/// Helper function to add finite field elements together
/// which is used throughout the cipher
fn FiniteAdd(a: u8, b: u8) -> u8{
    a ^ b
}

/// Helper function to multiply finite field elements
/// together, which is used throught the cipher. Used 
/// in FiniteMult function
fn xtime(a: u8) -> u8 {
    let mx = 0x1b;
    let mut ret: u16 = a as u16;

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
    for i in 0..8{
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
fn AddRoundKey(state: &Vec<Vec<u8>>, thing: u32) -> u32 {
    0
}

/// Transformation in the Inverse Cipher that is the inverse
/// of MixColumns
fn InvMixColumns() -> u32 {
    0
}

/// Transformation in the Inverse Cipher that is the inverse
/// of ShiftRows
fn InvShiftRows() -> u32 {
    0
}

/// Transformation in the Inverse Cipher that is the inverse
/// of SubBytes
fn InvSubBytes() -> u32 {
    0
}

/// Transformation in the Cipher that takes all of the columns
/// of the State and mixes their data (independently of eachother)
/// to produce new columns
fn MixColumns(state: &mut Vec<Vec<u8>>) {
    let matrix = [[2,3,1,1],
                  [1,2,3,1],
                  [1,1,2,3],
                  [3,1,1,2]];
}

/// Used in the Key Expansion routine that takes a 4-byte word
/// and performs a cyclic permutation
fn RotWord() -> u32 {
    0
}

/// Transformation in the Cipher that processes the State by
/// cyclically shifting the last three rows of the State by
/// different offsets
fn ShiftRows(state: &mut Vec<Vec<u8>>) {
    // shift each row by its column index
    for row in 0..state.len() {
        let mut tmp_arr: Vec<u8> = Vec::with_capacity(state[row].len());
        for col in 0..state[row].len(){
            tmp_arr[col] = state[row][(col+row)%4] // get the value at index+offset, looping
        }
        // copy the data from the temporary array back into state
        for j in 0..state[row].len(){
            state[row][j] = tmp_arr[j];
        }
    }
}

/// Transformation in the Cipher that processes the State
/// using a non-linear byte substitution table (S-box) that
/// operates on each of the State bytes independently
fn SubBytes(sbox: &Vec<Vec<u8>>, state: &mut Vec<Vec<u8>>) -> u32 {
    // to transform a byte, we do this: 
    // say we had a value s(1,1) = 0x53
    // to compute the replaced value, we would go to 
    // sbox[0x5][0x3] and replace 0x53 with the byte 
    // at the index (which should be 0xed)

    // for each row...
    for i in 0..state.len() {
        // for each column
        for j in 0..state[i].len(){
            // replace the byte with the byte in sbox[bit&0xf0][bit&0xf]
            let bit = state[i][j];
            let x = bit & 0xf0;
            let y = bit & 0xf;
            state[i][j] = sbox[x as usize][y as usize];
        }
    }

    0
}

/// Used in the Key Expansion routine that takes 4-byte
/// input word and applies an S-box to each of the four
/// bytes to produce an output word.
fn SubWord() -> u32 {
    0
}

/// The function that actually encodes a block
/// Note in  -> vec<u8> [4 x Nb]
///      out -> vec<u8> [4 x Nb]
///      w   -> vec<u32> [Nb x (Nr+1)]
fn Cipher(input: &mut Vec<Vec<u8>>, sbox: &Vec<Vec<u8>>,
          w: Vec<Vec<u32>>, Nr: u32, Nb: u32)
{
    //let state:Vec<Vec<u8>> = vec![vec![0; 4]; Nb as usize];
    let state = input;
    
    AddRoundKey(state, w[0][(Nb-1) as usize]); // See Sec. 5.1.4
    let cap = Nr-1;
    for round in 1..cap {
        SubBytes(sbox, state); // See Sec. 5.1.1
        ShiftRows(state); // See Sec. 5.1.2
        MixColumns(state); // See Sec. 5.1.3
        AddRoundKey(state, w[(round*Nb) as usize][((round+1)*Nb-1) as usize]);
    }
        
    
    SubBytes(sbox, state);
    ShiftRows(state);
    AddRoundKey(state, w[(Nr*Nb) as usize][((Nr+1)*Nb-1) as usize]);
}

/// Main Function
fn main() {
    // our fancy little lookup table, called the S-box
    let sbox = [[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
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



    let K: Vec<u8> = Vec::new();   // the cipher key
    let Nb: u32 = 4;        // Number of columns comprising the state
    // TODO: see if modifying this could be cool?

    // note that we are using the
    // below values for AES-256
    let Nk: u32 = 4;        // Number of 32-bit words comprising the Cipher Key
    let Nr: u8  = 10;       // Number or rounds, function of Nk and Nb

    let Rcon: Vec<u32> = Vec::new();  // Round constant word array


    println!("{}", FiniteMult(0x57,0x13));
}
