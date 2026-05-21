//! Step #9 (Grill Q15-E): in-process offset dumper.
//!
//! Resolves engine globals (GWorld / GNames / GObjects, plus per-target
//! sigs) by sig-scanning the live target image via `OPHION_OP_READ_SCATTER`.
//! Pattern bytes live in a [`SigDef`] table the caller supplies; this module
//! is intentionally engine-agnostic so Lyra (UE5) and TslGame (UE4 + PUBG
//! patches) reuse the same plumbing.
//!
//! Cache layout (`%LOCALAPPDATA%\Microsoft\Windows\WER\Temp\<file>`):
//!   - 8 bytes  : magic `OPHNDMP\0`
//!   - 4 bytes  : version (currently 1)
//!   - 4 bytes  : `IMAGE_NT_HEADERS.FileHeader.TimeDateStamp` of the image
//!   - 4 bytes  : entry count N
//!   - N * 64   : `[ name[56] u8 (NUL-padded) ][ va u64 ]`
//!
//! Stamp mismatch -> drop cache + redump. Same target rebuilds the cache
//! once the game patches.

use crate::hv_pipe::{self, ScatterEntry, ScatterResp, Session, Target, SCATTER_RESP_RESERVED_BYTES};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Cache magic — `OPHNDMP\0` little-endian byte sequence.
const CACHE_MAGIC_BYTES: [u8; 8] = *b"OPHNDMP\0";
pub const CACHE_VERSION: u32 = 1;
pub const CACHE_NAME_BYTES: usize = 56;
pub const CACHE_RECORD_BYTES: usize = CACHE_NAME_BYTES + 8;

/// Single .text scan chunk size. Sized so `read_scatter` returns in one
/// VMCALL plus a 4 KiB header headroom — `METHOD_OUT_DIRECT` MDLs handle
/// the lock + map without per-chunk allocation churn.
pub const SCAN_CHUNK_BYTES: usize = 1 * 1024 * 1024;
/// Overlap slack on each chunk so a pattern spanning the seam is still
/// caught. Must be `>= max(pattern.len() + max_resolver_offset)`.
pub const SCAN_CHUNK_OVERLAP: usize = 64;

/// Pattern token. Bytes are matched literally; wildcards are skipped.
#[derive(Debug, Clone, Copy)]
pub enum Tok {
    Byte(u8),
    Any,
}

/// Compiled sig pattern. Construct via [`parse_ida`] (e.g. `"48 8B ? 0D ? ? ? ?"`).
#[derive(Debug, Clone)]
pub struct Pattern {
    pub tokens: Vec<Tok>,
}

impl Pattern {
    pub fn len(&self) -> usize {
        self.tokens.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Parse an IDA-style pattern: hex bytes separated by whitespace, `?` or
/// `??` for wildcards. Examples:
///   "48 8B 05 ? ? ? ?"
///   "E8 ?? ?? ?? ?? 48 8B C8"
pub fn parse_ida(s: &str) -> Result<Pattern> {
    let mut tokens = Vec::new();
    for tok in s.split_ascii_whitespace() {
        if tok == "?" || tok == "??" {
            tokens.push(Tok::Any);
            continue;
        }
        if tok.len() != 2 {
            bail!("bad token in IDA sig: {tok:?}");
        }
        let v = u8::from_str_radix(tok, 16).with_context(|| format!("bad hex {tok:?}"))?;
        tokens.push(Tok::Byte(v));
    }
    if tokens.is_empty() {
        bail!("empty IDA sig");
    }
    Ok(Pattern { tokens })
}

/// How to convert a sig-match VA into the resolved global VA.
#[derive(Debug, Clone, Copy)]
pub enum Resolver {
    /// The match VA itself is the answer (rare; used for "this is a code
    /// stub I want the address of").
    Direct,
    /// Treat the 4 bytes at `match_va + off` as a RIP-relative i32. Result
    /// = `match_va + off + 4 + i32_at(match_va + off)`. Standard x86_64
    /// `mov rax, [rip+disp32]` pattern.
    RipRel32 { off: usize },
    /// Treat the 8 bytes at `match_va + off` as an absolute u64.
    Abs64 { off: usize },
}

/// Sig + name + resolver triplet. Names are stable cache keys.
#[derive(Debug, Clone)]
pub struct SigDef {
    pub name: String,
    pub pattern: Pattern,
    pub resolver: Resolver,
}

impl SigDef {
    pub fn new(name: &str, ida: &str, resolver: Resolver) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            pattern: parse_ida(ida)?,
            resolver,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub base: u64,
    pub size: u64,
    pub timedate_stamp: u32,
    pub sections: Vec<Section>,
}

impl PeInfo {
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }
}

/// Read PE header info (TimeDateStamp + section table) from the resolved
/// target. Performs three small reads; cheap.
pub fn read_pe_info(session: &Session, target: &Target) -> Result<PeInfo> {
    let mut dos = [0u8; 64];
    hv_pipe::read(session, target.base, &mut dos).context("read DOS header")?;
    if &dos[0..2] != b"MZ" {
        bail!("target.base is not MZ");
    }
    let e_lfanew = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;

    let mut nt = [0u8; 264];
    hv_pipe::read(session, target.base + e_lfanew, &mut nt).context("read NT headers")?;
    if &nt[0..4] != b"PE\0\0" {
        bail!("PE signature missing");
    }
    let timedate_stamp = u32::from_le_bytes(nt[8..12].try_into().unwrap());
    let num_sections = u16::from_le_bytes(nt[6..8].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(nt[20..22].try_into().unwrap()) as u64;
    let section_table_va = target.base + e_lfanew + 24 + opt_size;

    if num_sections == 0 || num_sections > 96 {
        bail!("ridiculous section count: {num_sections}");
    }

    let mut sect_buf = vec![0u8; num_sections * 40];
    hv_pipe::read(session, section_table_va, &mut sect_buf).context("read section table")?;

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = &sect_buf[i * 40..(i + 1) * 40];
        let raw_name = &s[0..8];
        let len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = std::str::from_utf8(&raw_name[..len])
            .unwrap_or("?")
            .to_string();
        let vsize = u32::from_le_bytes(s[8..12].try_into().unwrap());
        let vaddr = u32::from_le_bytes(s[12..16].try_into().unwrap());
        let chars = u32::from_le_bytes(s[36..40].try_into().unwrap());
        sections.push(Section {
            name,
            virtual_address: vaddr,
            virtual_size: vsize,
            characteristics: chars,
        });
    }

    Ok(PeInfo {
        base: target.base,
        size: target.size,
        timedate_stamp,
        sections,
    })
}

/// Naive byte-wise sig matcher. Returns absolute VA of every match in
/// `[chunk_va, chunk_va + chunk.len() - pattern.len()]`.
fn match_pattern(chunk: &[u8], chunk_va: u64, pattern: &Pattern, out: &mut Vec<u64>) {
    let plen = pattern.tokens.len();
    if chunk.len() < plen {
        return;
    }
    let last = chunk.len() - plen;
    'outer: for i in 0..=last {
        for j in 0..plen {
            match pattern.tokens[j] {
                Tok::Any => {}
                Tok::Byte(b) => {
                    if chunk[i + j] != b {
                        continue 'outer;
                    }
                }
            }
        }
        out.push(chunk_va + i as u64);
    }
}

/// Sig-scan a section. Pulls it down in [`SCAN_CHUNK_BYTES`]-sized reads,
/// matches each pattern, and returns map: sig name -> all absolute match VAs.
///
/// Each chunk overlaps the next by `SCAN_CHUNK_OVERLAP` so a pattern straddling
/// the seam is found exactly once (matches in the overlap of chunk N+1 also
/// land in chunk N's tail, so we de-dup at the end).
pub fn scan_section_for_sigs(
    session: &Session,
    base: u64,
    section: &Section,
    sigs: &[SigDef],
) -> Result<HashMap<String, Vec<u64>>> {
    let sect_va = base + section.virtual_address as u64;
    let sect_size = section.virtual_size as usize;
    let mut by_sig: HashMap<String, Vec<u64>> = sigs
        .iter()
        .map(|s| (s.name.clone(), Vec::new()))
        .collect();

    let mut off = 0usize;
    while off < sect_size {
        let want = (sect_size - off).min(SCAN_CHUNK_BYTES + SCAN_CHUNK_OVERLAP);
        let mut buf = vec![0u8; want];
        hv_pipe::read(session, sect_va + off as u64, &mut buf)
            .with_context(|| format!("scan read at +0x{:x}", off))?;
        for sig in sigs {
            match_pattern(&buf, sect_va + off as u64, &sig.pattern, by_sig.get_mut(&sig.name).unwrap());
        }
        if want < SCAN_CHUNK_BYTES + SCAN_CHUNK_OVERLAP {
            break; // tail
        }
        off += SCAN_CHUNK_BYTES; // advance by core, keep overlap
    }

    // De-dup matches per sig (overlap region can produce double hits).
    for v in by_sig.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    Ok(by_sig)
}

/// Apply a sig's resolver to the first (or only) match. For sigs expected
/// to land on a unique callsite (`GWorld` mov), zero or many matches => err.
pub fn resolve_first(
    session: &Session,
    sig: &SigDef,
    matches: &[u64],
) -> Result<u64> {
    if matches.is_empty() {
        bail!("sig {} no match", sig.name);
    }
    if matches.len() > 1 {
        log::warn!(
            "sig {} ambiguous: {} matches; using first 0x{:x}",
            sig.name,
            matches.len(),
            matches[0]
        );
    }
    apply_resolver(session, matches[0], &sig.resolver)
}

fn apply_resolver(session: &Session, match_va: u64, resolver: &Resolver) -> Result<u64> {
    match *resolver {
        Resolver::Direct => Ok(match_va),
        Resolver::RipRel32 { off } => {
            let mut buf = [0u8; 4];
            hv_pipe::read(session, match_va + off as u64, &mut buf)?;
            let disp = i32::from_le_bytes(buf) as i64;
            // RIP at instruction after the disp = match_va + off + 4
            let next_rip = match_va + off as u64 + 4;
            Ok((next_rip as i64 + disp) as u64)
        }
        Resolver::Abs64 { off } => {
            let mut buf = [0u8; 8];
            hv_pipe::read(session, match_va + off as u64, &mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

/// Top-level dump entry: scan `.text` (and optionally `.rdata`/`.data`) for
/// every supplied sig, resolve each to a single VA, return name->VA map plus
/// the image's TimeDateStamp.
#[derive(Debug, Clone)]
pub struct DumpResult {
    pub timedate_stamp: u32,
    pub entries: HashMap<String, u64>,
}

/// Sections to scan, in order. `.text` is always tried first; sigs that
/// don't land there fall through to the next named section.
pub const SCAN_SECTIONS: &[&str] = &[".text", ".rdata", ".data"];

pub fn dump(session: &Session, target: &Target, sigs: &[SigDef]) -> Result<DumpResult> {
    let pe = read_pe_info(session, target)?;
    log::info!(
        "PE base=0x{:x} size=0x{:x} stamp=0x{:08x} sections={}",
        pe.base,
        pe.size,
        pe.timedate_stamp,
        pe.sections.len()
    );

    let mut all_matches: HashMap<String, Vec<u64>> =
        sigs.iter().map(|s| (s.name.clone(), Vec::new())).collect();

    for sect_name in SCAN_SECTIONS {
        let Some(sect) = pe.section(sect_name) else {
            continue;
        };
        let by_sig = scan_section_for_sigs(session, pe.base, sect, sigs)?;
        for (k, mut v) in by_sig {
            all_matches.get_mut(&k).unwrap().append(&mut v);
        }
    }

    let mut entries = HashMap::with_capacity(sigs.len());
    for sig in sigs {
        let matches = all_matches.remove(&sig.name).unwrap_or_default();
        let va = resolve_first(session, sig, &matches)
            .with_context(|| format!("resolve sig {}", sig.name))?;
        log::info!("sig {} -> 0x{:x}", sig.name, va);
        entries.insert(sig.name.clone(), va);
    }

    Ok(DumpResult {
        timedate_stamp: pe.timedate_stamp,
        entries,
    })
}

/// Cache file location. Keyed by a caller-supplied name so different
/// targets (TslGame vs Lyra) don't stomp each other's tables.
pub fn cache_path(filename: &str) -> PathBuf {
    let mut p = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    p.push("Microsoft\\Windows\\WER\\Temp");
    p.push(filename);
    p
}

pub fn cache_save(filename: &str, dump: &DumpResult) -> Result<()> {
    let path = cache_path(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut buf = Vec::with_capacity(16 + dump.entries.len() * CACHE_RECORD_BYTES);
    buf.extend_from_slice(&CACHE_MAGIC_BYTES);
    buf.extend_from_slice(&CACHE_VERSION.to_le_bytes());
    buf.extend_from_slice(&dump.timedate_stamp.to_le_bytes());
    buf.extend_from_slice(&(dump.entries.len() as u32).to_le_bytes());
    let mut keys: Vec<&String> = dump.entries.keys().collect();
    keys.sort(); // deterministic file
    for k in keys {
        let v = dump.entries[k];
        let mut name_buf = [0u8; CACHE_NAME_BYTES];
        let bytes = k.as_bytes();
        let n = bytes.len().min(CACHE_NAME_BYTES);
        name_buf[..n].copy_from_slice(&bytes[..n]);
        buf.extend_from_slice(&name_buf);
        buf.extend_from_slice(&v.to_le_bytes());
    }
    std::fs::write(&path, &buf)
        .with_context(|| format!("write cache {}", path.display()))?;
    Ok(())
}

pub fn cache_load(filename: &str, expected_stamp: u32) -> Result<DumpResult> {
    let path = cache_path(filename);
    let buf = std::fs::read(&path)
        .with_context(|| format!("read cache {}", path.display()))?;
    if buf.len() < 20 {
        bail!("cache too small ({} bytes)", buf.len());
    }
    if &buf[0..8] != CACHE_MAGIC_BYTES {
        bail!("cache magic mismatch");
    }
    let ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if ver != CACHE_VERSION {
        bail!("cache version {} != expected {}", ver, CACHE_VERSION);
    }
    let stamp = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    if stamp != expected_stamp {
        bail!(
            "cache stamp 0x{:08x} != target 0x{:08x} (rebuild)",
            stamp,
            expected_stamp
        );
    }
    let count = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let need = 20 + count * CACHE_RECORD_BYTES;
    if buf.len() < need {
        bail!("cache truncated: {} < {}", buf.len(), need);
    }
    let mut entries = HashMap::with_capacity(count);
    let mut off = 20;
    for _ in 0..count {
        let raw_name = &buf[off..off + CACHE_NAME_BYTES];
        let n = raw_name.iter().position(|&b| b == 0).unwrap_or(CACHE_NAME_BYTES);
        let name = std::str::from_utf8(&raw_name[..n])
            .map_err(|e| anyhow!("cache name utf8: {e}"))?
            .to_string();
        let va = u64::from_le_bytes(
            buf[off + CACHE_NAME_BYTES..off + CACHE_RECORD_BYTES]
                .try_into()
                .unwrap(),
        );
        entries.insert(name, va);
        off += CACHE_RECORD_BYTES;
    }
    Ok(DumpResult {
        timedate_stamp: stamp,
        entries,
    })
}

/// Convenience: load if cache valid for current image stamp, else dump
/// fresh + persist. The full PE info read is reused either way.
pub fn dump_or_load(
    session: &Session,
    target: &Target,
    sigs: &[SigDef],
    cache_filename: &str,
) -> Result<DumpResult> {
    let pe = read_pe_info(session, target)?;
    if let Ok(cached) = cache_load(cache_filename, pe.timedate_stamp) {
        log::info!(
            "dumper: cache hit for stamp 0x{:08x} ({} entries)",
            cached.timedate_stamp,
            cached.entries.len()
        );
        return Ok(cached);
    }
    let fresh = dump(session, target, sigs)?;
    cache_save(cache_filename, &fresh).ok();
    Ok(fresh)
}

/// Quick batch read helper for callers wiring sig results into deeper SDK
/// walks. Pulls many `(va, len)` pairs in one VMCALL via READ_SCATTER and
/// returns the raw bytes per request, in input order.
pub fn read_batch(session: &Session, requests: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    if requests.len() > hv_pipe::SCATTER_MAX_ENTRIES {
        bail!(
            "read_batch over scatter cap: {} > {}",
            requests.len(),
            hv_pipe::SCATTER_MAX_ENTRIES
        );
    }
    let total: usize = requests.iter().map(|&(_, n)| n).sum();
    let mut out = vec![0u8; SCATTER_RESP_RESERVED_BYTES as usize + total];
    let mut entries = Vec::with_capacity(requests.len());
    let mut off = SCATTER_RESP_RESERVED_BYTES;
    for &(va, n) in requests {
        entries.push(ScatterEntry {
            src_va: va,
            len: n as u32,
            out_offset: off,
        });
        off += n as u32;
    }
    let resp: ScatterResp = hv_pipe::read_scatter(session, &entries, &mut out)?;
    if resp.status != 0 {
        bail!(
            "read_batch scatter status={} ok={} fail={}",
            resp.status,
            resp.ok_count,
            resp.fail_count
        );
    }
    let mut results = Vec::with_capacity(requests.len());
    let mut o = SCATTER_RESP_RESERVED_BYTES as usize;
    for &(_, n) in requests {
        results.push(out[o..o + n].to_vec());
        o += n;
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_parses_basic() {
        let p = parse_ida("48 8B 05 ? ? ? ?").unwrap();
        assert_eq!(p.tokens.len(), 7);
        assert!(matches!(p.tokens[0], Tok::Byte(0x48)));
        assert!(matches!(p.tokens[1], Tok::Byte(0x8B)));
        assert!(matches!(p.tokens[3], Tok::Any));
    }

    #[test]
    fn match_finds_unique() {
        let pat = parse_ida("DE AD BE EF").unwrap();
        let hay = b"\x00\x00\xde\xad\xbe\xef\x00\x00";
        let mut hits = Vec::new();
        match_pattern(hay, 0x1000, &pat, &mut hits);
        assert_eq!(hits, vec![0x1002]);
    }

    #[test]
    fn match_handles_wildcards() {
        let pat = parse_ida("48 8B ? 05").unwrap();
        let hay = b"\x48\x8B\xC0\x05\x48\x8B\x44\x05\x48\x8B\x99\x06";
        let mut hits = Vec::new();
        match_pattern(hay, 0, &pat, &mut hits);
        assert_eq!(hits, vec![0, 4]);
    }

    #[test]
    fn cache_round_trip() {
        let mut entries = HashMap::new();
        entries.insert("GWorld".to_string(), 0x7ff7_dead_beefu64);
        entries.insert("GNames".to_string(), 0x7ff7_cafe_babeu64);
        let dump = DumpResult {
            timedate_stamp: 0x12345678,
            entries: entries.clone(),
        };
        let fname = "ophion_dumper_test.bin";
        cache_save(fname, &dump).unwrap();
        let back = cache_load(fname, 0x12345678).unwrap();
        assert_eq!(back.timedate_stamp, 0x12345678);
        assert_eq!(back.entries, entries);
        // Stamp mismatch must reject
        assert!(cache_load(fname, 0xDEADBEEF).is_err());
        let _ = std::fs::remove_file(cache_path(fname));
    }
}
