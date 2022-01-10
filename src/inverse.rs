use crate::common::*;
use crate::constants::*;
use crate::helpers::*;


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

/// The inverse of `Cipher`
pub fn InvCipher(input: &Vec<u8>, Rcon: Vec<u8>) -> Vec<u8> {
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
