//! Semantic-facts-csharp — Parser-derived semantic facts for C#.
//!
//! Provides `semantic-facts@csharp/v1` by consuming parser capabilities:
//! - `parse.call-sites@csharp/v1`
//! - `parse.retrieval@csharp/v1`

#![no_std]

extern crate alloc;
use alloc::string::ToString;
use alloc::vec::Vec;

use basalt_plugin_sdk::prelude::*;
use basalt_plugin_sdk::facts::{SemanticFact, SymbolKind, serialize_facts};

// ── Plugin metadata ────────────────────────────────────────────────────────

basalt_plugin_meta! {
    name:              "semantic-facts-csharp",
    version:           env!("CARGO_PKG_VERSION"),
    hook_flags:        CAP_CAPABILITY_HANDLE | CAP_API_INDEX,
    provides:          "semantic-facts@csharp/v1",
    requires:          "parse.call-sites@csharp/v1\nparse.retrieval@csharp/v1",
    optional_requires: "",
    file_globs:        "**/*.cs",
    activates_on:      "",
    activation_events: "",
}

// ── Capability handle export ───────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn basalt_capability_handle(
    cap_ptr: *const u8,
    cap_len: usize,
    req_ptr: *const u8,
    req_len: usize,
) -> i64 {
    let _ = (cap_ptr, cap_len);
    if req_ptr.is_null() || req_len == 0 { return pack_empty(); }
    let request = unsafe { core::slice::from_raw_parts(req_ptr, req_len) };

    if request.len() < 4 { return pack_error(-1002); }
    let src_len = u32::from_le_bytes([request[0], request[1], request[2], request[3]]) as usize;
    if request.len() < 4 + src_len { return pack_error(-1002); }
    let src = &request[4..4 + src_len];
    if src.is_empty() { return pack_empty(); }

    match derive_semantic_facts(src) {
        Ok(facts) => pack_success(facts),
        Err(code) => pack_error(code),
    }
}

// ── Semantic fact derivation ───────────────────────────────────────────────

fn derive_semantic_facts(src: &[u8]) -> Result<Vec<u8>, i64> {
    let call_sites_raw = invoke_parse_call_sites(src).map_err(|_| -1003)?;
    let retrieval_raw = invoke_parse_retrieval(src).map_err(|_| -1003)?;

    let call_sites = decode_call_sites(&call_sites_raw);
    let retrieval = decode_retrieval(&retrieval_raw);

    let mut facts: Vec<SemanticFact> = Vec::new();
    derive_declarations(&retrieval, &mut facts);
    derive_call_edges(&call_sites, &mut facts);
    // C# specific relationships could be added here (Inheritance etc)
    
    Ok(serialize_facts(&facts))
}

// ── Parser capability invocations ──────────────────────────────────────────

fn invoke_parse_call_sites(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&16384u32.to_le_bytes());
    invoke_capability("parse.call-sites@csharp/v1", &request).map_err(|_| -1003)
}

fn invoke_parse_retrieval(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&8192u32.to_le_bytes());
    invoke_capability("parse.retrieval@csharp/v1", &request).map_err(|_| -1003)
}

// ── Parser response decoding ───────────────────────────────────────────────

fn decode_call_sites(data: &[u8]) -> Vec<(u32, &str)> {
    if data.len() < 4 { return Vec::new(); }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut sites = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 68 > data.len() { break; }
        let offset = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let name_bytes = &data[pos + 4..pos + 68];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        if let Ok(name) = core::str::from_utf8(&name_bytes[..nul]) {
            if !name.is_empty() { sites.push((offset, name)); }
        }
        pos += 68;
    }
    sites
}

fn decode_retrieval(data: &[u8]) -> Vec<(u32, u32, &str, u8)> {
    if data.len() < 4 { return Vec::new(); }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut chunks = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 104 > data.len() { break; }
        let offset = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        let length = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);
        let label_bytes = &data[pos + 8..pos + 103];
        let kind = data[pos + 103];
        let nul = label_bytes.iter().position(|&b| b == 0).unwrap_or(95);
        if let Ok(label) = core::str::from_utf8(&label_bytes[..nul]) {
            let label = label.trim();
            if !label.is_empty() && length > 0 { chunks.push((offset, length, label, kind)); }
        }
        pos += 104;
    }
    chunks
}

// ── Fact derivation from parser output ─────────────────────────────────────

fn derive_declarations(retrieval: &[(u32, u32, &str, u8)], facts: &mut Vec<SemanticFact>) {
    for &(offset, length, label, kind) in retrieval {
        match kind {
            1 => { // module (namespace)
                let name = label.strip_prefix("namespace ").unwrap_or(label);
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Module,
                    offset, length, name: name.to_string(), qualified_name: None,
                });
            }
            2 => { // type
                let name = label.strip_prefix("type ").or_else(|| label.strip_prefix("class ")).or_else(|| label.strip_prefix("struct ")).or_else(|| label.strip_prefix("enum ")).unwrap_or(label);
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Type,
                    offset, length, name: name.to_string(), qualified_name: None,
                });
            }
            3 => { // function (method)
                let name = label.strip_prefix("function ").unwrap_or(label);
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Function,
                    offset, length, name: name.to_string(), qualified_name: None,
                });
            }
            7 => { // interface
                let name = label.strip_prefix("interface ").unwrap_or(label);
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Interface,
                    offset, length, name: name.to_string(), qualified_name: None,
                });
            }
            _ => {}
        }
    }
}

fn derive_call_edges(call_sites: &[(u32, &str)], facts: &mut Vec<SemanticFact>) {
    for &(offset, callee) in call_sites {
        facts.push(SemanticFact::Calls {
            caller_offset: offset,
            caller_length: callee.len() as u32,
            callee: callee.to_string(),
        });
    }
}
