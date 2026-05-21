//! Xenuine pointer-decrypt — runtime opcode emulation.
//!
//! PUBG's `XenuineDecrypt` function changes the decrypt math every patch.
//! Hardcoding constants ages out in days. The community-validated bypass
//! (UC pages 943-952, hawad post) is to read the first 80 bytes of the
//! function at runtime, parse the recurring opcode templates, extract the
//! per-build constants, and emulate the math in user space:
//!
//! | opcode bytes | mnemonic       | extract |
//! |--------------|----------------|---------|
//! | `48 81 F1`   | `xor rcx, imm32` | imm32 |
//! | `48 81 C1`   | `add rcx, imm32` | imm32 |
//! | `48 29 ??`   | `sub rcx, reg`   | reg id |
//! | `48 C1 C1`   | `rol rcx, imm8`  | imm8  |
//!
//! Status: skeleton only. Wired through `PubgOffsets::xenuine_decrypt_rva`
//! (already populated by the JSON loader). Caller pulls the prologue via
//! SCATTER and feeds it to [`parse_program`]; [`run`] folds the resulting
//! op list against an encrypted pointer.
//!
//! TODO: full opcode coverage (PUBG's variant set has expanded over the
//! years; ROR variant, MOV imm-to-reg, register selection beyond rcx).

use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub enum XOp {
    XorImm32(u32),
    AddImm32(u32),
    SubReg, // placeholder — register identity ignored for now
    Rol(u8),
}

/// Walks the byte sequence and emits a program of XOps. Stops on the first
/// unrecognised opcode (typically the function epilogue or a control-flow
/// instruction).
pub fn parse_program(bytes: &[u8]) -> Vec<XOp> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        // 48 81 F1 imm32  -> xor rcx, imm32
        if bytes[i] == 0x48 && bytes[i + 1] == 0x81 && bytes[i + 2] == 0xF1 && i + 7 <= bytes.len() {
            let imm = u32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
            out.push(XOp::XorImm32(imm));
            i += 7;
            continue;
        }
        // 48 81 C1 imm32  -> add rcx, imm32
        if bytes[i] == 0x48 && bytes[i + 1] == 0x81 && bytes[i + 2] == 0xC1 && i + 7 <= bytes.len() {
            let imm = u32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
            out.push(XOp::AddImm32(imm));
            i += 7;
            continue;
        }
        // 48 29 ??  -> sub rcx, reg (3-byte)
        if bytes[i] == 0x48 && bytes[i + 1] == 0x29 {
            out.push(XOp::SubReg);
            i += 3;
            continue;
        }
        // 48 C1 C1 imm8  -> rol rcx, imm8
        if bytes[i] == 0x48 && bytes[i + 1] == 0xC1 && bytes[i + 2] == 0xC1 && i + 4 <= bytes.len() {
            out.push(XOp::Rol(bytes[i + 3]));
            i += 4;
            continue;
        }
        break;
    }
    out
}

/// Apply the parsed program to an encrypted u64. Caller decides whether to
/// treat the result as a UWorld pointer, FName index, or other value.
pub fn run(prog: &[XOp], encrypted: u64) -> u64 {
    let mut v = encrypted;
    for op in prog {
        match *op {
            XOp::XorImm32(k) => v ^= k as u64,
            XOp::AddImm32(k) => v = v.wrapping_add(k as u64),
            XOp::SubReg => {} // TODO: needs companion-register tracking
            XOp::Rol(n) => v = v.rotate_left(n as u32),
        }
    }
    v
}

/// Convenience: caller feeds the function prologue + encrypted u64,
/// receives the decrypted u64. Errors only if the prologue is empty.
pub fn decrypt(bytes: &[u8], encrypted: u64) -> Result<u64> {
    let prog = parse_program(bytes);
    if prog.is_empty() {
        anyhow::bail!("XenuineDecrypt prologue produced no ops");
    }
    Ok(run(&prog, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_then_rol() {
        // 48 81 F1 78 56 34 12        xor rcx, 0x12345678
        // 48 C1 C1 0D                 rol rcx, 13
        let bytes = [
            0x48, 0x81, 0xF1, 0x78, 0x56, 0x34, 0x12, 0x48, 0xC1, 0xC1, 0x0D,
        ];
        let prog = parse_program(&bytes);
        assert_eq!(prog.len(), 2);
        match prog[0] {
            XOp::XorImm32(k) => assert_eq!(k, 0x12345678),
            _ => panic!("first op should be xor"),
        }
        match prog[1] {
            XOp::Rol(n) => assert_eq!(n, 0x0D),
            _ => panic!("second op should be rol"),
        }
    }

    #[test]
    fn run_xor_round_trip() {
        let prog = vec![XOp::XorImm32(0xDEADBEEF)];
        let v = run(&prog, 0xCAFEBABE_u64);
        // applying same XOR twice round-trips
        let back = run(&prog, v);
        assert_eq!(back, 0xCAFEBABE);
    }

    #[test]
    fn empty_prologue_errors() {
        assert!(decrypt(&[0x90, 0xC3], 0x1234).is_err());
    }
}
