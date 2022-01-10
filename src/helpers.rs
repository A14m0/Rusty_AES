use std::convert::TryInto;
use crate::constants::*;


/// Helper function that places the input in a proper state array
pub fn CopyToState(input: Vec<u8>) -> Vec<Vec<u8>> {
    let mut state: Vec<Vec<u8>> = vec![vec![0;Nb as usize]; 4];
    for row in 0..4 {
        for col in 0..Nb as usize {
            state[row][col] = input[row + 4*col];
        }
    }
    state
} 

/// Helper function that converts a state to an output vector
pub fn ToOutput(state: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; 128];

    for row in 0..4usize {
        for col in 0..(Nb as usize) {
            out[4*col + row] = state[row][col];
        }
    }
    out
}

/// Helper function that converts 4 bytes into a 32-bit word
pub fn MakeWord(a: u8, b: u8, c: u8, d: u8) -> u32 {
    let mut o = 0;
    o = (a as u32) << 24;
    o += (b as u32) << 16;
    o += (c as u32) << 8;
    o += d as u32;

    o
}

/// Helper function that converts a word to 4 bytes
pub fn MakeBytes(a: u32) -> [u8; 4] {
    let mut o = [0u8; 4];
    o[3] = (a & 0xff).try_into().unwrap();
    o[2] = ((a >> 8) & 0xff).try_into().unwrap();
    o[1] = ((a >> 16) & 0xff).try_into().unwrap();
    o[0] = ((a >> 24) & 0xff).try_into().unwrap();
    
    o
}

/// Creates a vector that holds a round constant
pub fn GenerateRoundConstant() -> Vec<u8> {
    Vec::new()
}