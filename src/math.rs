/// Helper function to add finite field elements together
/// which is used throughout the cipher
pub fn FiniteAdd(a: u8, b: u8) -> u8{
    a ^ b
}

/// Helper function to multiply finite field elements
/// together, which is used throught the cipher. Used 
/// in FiniteMult function
pub fn xtime(a: u8) -> u8 {
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
pub fn FiniteMult(a: u8, b: u8) -> u8 {
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


