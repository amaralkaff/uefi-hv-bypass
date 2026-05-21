//! Stage 1 smoke harness for the Ophion VMCALL pipe (Grill Q23-A).
//!
//! Validates the full IOCTL surface end-to-end without touching any AC-
//! protected process. Targets `notepad.exe` for RESOLVE/READ/WRITE.
//!
//! Cycle:
//!   1. open device, REGISTER (creates Session)
//!   2. RESOLVE("notepad.exe")
//!   3. READ_SCATTER first 4 bytes at notepad image base, expect "MZ"
//!   4. UNREGISTER (handle drop runs IOCTL_HV_UNREGISTER)
//!
//! Run with `--cycles N` for leak-check loops:
//!   hv_smoke.exe                  # single cycle, prints diagnostics
//!   hv_smoke.exe --cycles 1000    # 1000-cycle loop, asserts no failures

use anyhow::{anyhow, bail, Context, Result};
use pubg_external::hv_pipe::{self, ScatterEntry, SCATTER_RESP_RESERVED_BYTES};
use pubg_external::sdk::dumper::{self, Resolver, SigDef};
use std::time::Instant;

fn parse_cycles() -> usize {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--cycles" {
            if let Some(n) = args.next() {
                if let Ok(v) = n.parse::<usize>() {
                    return v;
                }
            }
        }
    }
    1
}

fn parse_flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn parse_kv(key: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == key {
            return args.next();
        }
    }
    None
}

fn run_one(verbose: bool) -> Result<()> {
    let session = hv_pipe::register().context("REGISTER")?;
    if verbose {
        println!(
            "REGISTER ok key=0x{:x} ophion_version=0x{:x}",
            session.key, session.version
        );
    }

    let target = hv_pipe::resolve_target(&session, "notepad.exe")
        .context("RESOLVE notepad.exe — is notepad running?")?;
    if verbose {
        println!(
            "RESOLVE ok pid={} base=0x{:x} size=0x{:x}",
            target.pid, target.base, target.size
        );
    }

    // READ first 4 bytes at notepad image base. Driver reserves bytes 0..16
    // of the gather buffer for ScatterResp; payload lands at out_offset >= 16.
    let entry = ScatterEntry {
        src_va: target.base,
        len: 4,
        out_offset: SCATTER_RESP_RESERVED_BYTES,
    };
    let mut out = vec![0u8; SCATTER_RESP_RESERVED_BYTES as usize + 4];
    let resp = hv_pipe::read_scatter(&session, &[entry], &mut out)
        .context("READ_SCATTER notepad image header")?;
    if resp.status != 0 || resp.ok_count != 1 {
        bail!(
            "READ_SCATTER status={} ok={} fail={}",
            resp.status,
            resp.ok_count,
            resp.fail_count
        );
    }
    let mz = &out[SCATTER_RESP_RESERVED_BYTES as usize..SCATTER_RESP_RESERVED_BYTES as usize + 2];
    if mz != b"MZ" {
        bail!(
            "MZ magic missing at notepad.base; got {:02x} {:02x}",
            mz[0],
            mz[1]
        );
    }
    if verbose {
        println!(
            "READ_SCATTER ok bytes=[{:02x} {:02x} {:02x} {:02x}] total={} ok={}",
            out[SCATTER_RESP_RESERVED_BYTES as usize],
            out[SCATTER_RESP_RESERVED_BYTES as usize + 1],
            out[SCATTER_RESP_RESERVED_BYTES as usize + 2],
            out[SCATTER_RESP_RESERVED_BYTES as usize + 3],
            resp.total_bytes,
            resp.ok_count,
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    if parse_flag("--percpu") {
        return dump_percpu();
    }

    if parse_flag("--dump") {
        return dump_target();
    }

    let cycles = parse_cycles();
    println!("hv_smoke: running {cycles} cycle(s)");

    if cycles == 1 {
        run_one(true).map_err(|e| anyhow!("smoke failed: {e:#}"))?;
        println!("hv_smoke: OK");
        return Ok(());
    }

    let start = Instant::now();
    let mut failures = 0usize;
    for i in 0..cycles {
        if let Err(e) = run_one(false) {
            failures += 1;
            eprintln!("cycle {i} failed: {e:#}");
            if failures >= 5 {
                bail!("aborting after {failures} failures");
            }
        }
        if (i + 1) % 100 == 0 {
            println!("hv_smoke: {} / {} OK", i + 1, cycles);
        }
    }
    let elapsed = start.elapsed();
    println!(
        "hv_smoke: {} cycles, {} failures, {:.2?} ({:.2} ms/cycle)",
        cycles,
        failures,
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / cycles as f64
    );
    if failures > 0 {
        bail!("{failures} cycle(s) failed");
    }
    Ok(())
}

/// Step #8: dump VMM per-CPU vmexit log. Requires an active session, so
/// register first then drain. Capacity 32 KiB covers 12-core layout
/// (12 * 1032 + header = ~12 KiB).
fn dump_percpu() -> Result<()> {
    let session = hv_pipe::register().context("REGISTER")?;
    println!("REGISTER ok key=0x{:x}", session.key);

    let snap = hv_pipe::get_vmm_percpu_log(&session, 32 * 1024)
        .context("GET_VMM_PERCPU_LOG")?;
    println!(
        "snapshot: cpu_count={} records_per_cpu={}",
        snap.cpu_count, snap.records_per_cpu
    );

    for (cpu, ring) in snap.ordered_per_cpu().iter().enumerate() {
        let head = snap.heads[cpu];
        let seq = snap.seqs[cpu];
        println!(
            "  cpu={} head={} seq={} (showing last {})",
            cpu,
            head,
            seq,
            ring.len()
        );
        for r in ring.iter().rev().take(8) {
            println!(
                "    tsc=0x{:016x} reason={:>4} qual=0x{:016x} rip=0x{:016x} tag=0x{:08x}",
                r.tsc, r.exit_reason, r.exit_qual, r.guest_rip, r.tag
            );
        }
    }
    Ok(())
}

/// Step #9: PE walker + sig-scan exerciser. Dumps the IMAGE_NT_HEADERS
/// of the named process, then scans `.text` for a self-locating sig that
/// always lands at the image base (`MZ\0\0`-prefix anchor) — this proves
/// the SCATTER → match → resolver pipeline works end-to-end without
/// requiring real PUBG sigs the harness can't ship.
///
///   hv_smoke --dump notepad.exe
///   hv_smoke --dump TslGame.exe --sig "48 8B 05 ? ? ? ?" --sig-name GWorld --resolver riprel32:3
///
/// Custom-sig path: --sig "<ida>" [--sig-name NAME] [--resolver direct|riprel32:OFF|abs64:OFF]
fn dump_target() -> Result<()> {
    let target_name = parse_kv("--dump")
        .ok_or_else(|| anyhow!("--dump requires a target process name"))?;
    let cache_filename = parse_kv("--cache")
        .unwrap_or_else(|| format!("ophion_dump_{}.bin", target_name.replace('.', "_")));

    let session = hv_pipe::register().context("REGISTER")?;
    println!("REGISTER ok key=0x{:x}", session.key);

    let target = hv_pipe::resolve_target(&session, &target_name)
        .with_context(|| format!("RESOLVE {target_name}"))?;
    println!(
        "RESOLVE ok pid={} base=0x{:x} size=0x{:x}",
        target.pid, target.base, target.size
    );

    let pe = dumper::read_pe_info(&session, &target).context("read PE header")?;
    println!(
        "PE: stamp=0x{:08x} sections={}",
        pe.timedate_stamp,
        pe.sections.len()
    );
    for s in &pe.sections {
        println!(
            "  {:8} VA=0x{:08x} VSize=0x{:08x} chars=0x{:08x}",
            s.name, s.virtual_address, s.virtual_size, s.characteristics
        );
    }

    // Build sig list. Default sanity sig: the MZ DOS header byte sequence
    // present at every PE base. Lands once exactly. Real engine sigs come
    // via --sig from the caller.
    let mut sigs = Vec::<SigDef>::new();
    let mut sig_args = std::env::args().skip(1);
    let mut last_pat: Option<String> = None;
    let mut last_name: Option<String> = None;
    let mut last_resolver: Option<String> = None;
    while let Some(a) = sig_args.next() {
        match a.as_str() {
            "--sig" => last_pat = sig_args.next(),
            "--sig-name" => last_name = sig_args.next(),
            "--resolver" => last_resolver = sig_args.next(),
            _ => {}
        }
    }
    if let Some(pat) = last_pat {
        let name = last_name.unwrap_or_else(|| "USER_SIG".to_string());
        let resolver = parse_resolver(last_resolver.as_deref())?;
        sigs.push(SigDef::new(&name, &pat, resolver)?);
    } else {
        // Fallback sanity sig — finds at least one byte sequence guaranteed
        // to live in `.rdata` of any UE/Win binary: the rich-header tag
        // "Rich" is reliable but not always; use IMAGE_DOS_SIGNATURE
        // doesn't live in .text. Use compiler-emitted "kernel32.dll"
        // import string, which exists in `.rdata` of every PE that imports
        // anything. Resolver = direct.
        sigs.push(SigDef::new(
            "kernel32_str",
            "6B 65 72 6E 65 6C 33 32 2E 64 6C 6C", // "kernel32.dll"
            Resolver::Direct,
        )?);
    }

    let dump = dumper::dump(&session, &target, &sigs).context("dump")?;
    println!("dump complete:");
    let mut keys: Vec<&String> = dump.entries.keys().collect();
    keys.sort();
    for k in keys {
        println!("  {} = 0x{:x}", k, dump.entries[k]);
    }

    dumper::cache_save(&cache_filename, &dump).ok();
    println!(
        "cached -> {}",
        dumper::cache_path(&cache_filename).display()
    );

    // Round-trip via dump_or_load to prove cache hit path works.
    let cached = dumper::dump_or_load(&session, &target, &sigs, &cache_filename)
        .context("dump_or_load")?;
    println!(
        "cache reload: stamp=0x{:08x} entries={}",
        cached.timedate_stamp,
        cached.entries.len()
    );
    Ok(())
}

fn parse_resolver(s: Option<&str>) -> Result<Resolver> {
    let Some(s) = s else { return Ok(Resolver::Direct) };
    if s == "direct" {
        return Ok(Resolver::Direct);
    }
    if let Some(rest) = s.strip_prefix("riprel32:") {
        return Ok(Resolver::RipRel32 {
            off: rest.parse().context("riprel32 offset")?,
        });
    }
    if let Some(rest) = s.strip_prefix("abs64:") {
        return Ok(Resolver::Abs64 {
            off: rest.parse().context("abs64 offset")?,
        });
    }
    bail!("unknown --resolver {s:?}; want direct | riprel32:OFF | abs64:OFF");
}
