use crate::common::*;
use crate::constants::*;
use crate::helpers::{CopyToState, ToOutput};
use crate::math::*;

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


/// The function that actually encodes a block
/// Note in  -> vec<u8> [4 x Nb]
///      out -> vec<u8> [4 x Nb]
///      w   -> vec<u32> [Nb x (Nr+1)]
pub fn Cipher(input: &Vec<u8>, Rcon: Vec<u8>) -> Vec<u8>
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

