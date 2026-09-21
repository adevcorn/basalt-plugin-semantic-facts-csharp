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
use basalt_plugin_sdk::facts::{SemanticFact, SymbolKind};
#[cfg(target_arch = "wasm32")]
use basalt_plugin_sdk::facts::serialize_facts;

// ── Plugin metadata ────────────────────────────────────────────────────────

basalt_plugin_meta! {
    name:              "semantic-facts-csharp",
    version:           env!("CARGO_PKG_VERSION"),
    // NOTE: core defines SEMANTIC_FACTS = 1 << 16 but the SDK has no const
    // for it yet; the literal keeps the declared flags truthful. The live
    // dispatch path keys off CAP_CAPABILITY_HANDLE + provides/globs.
    hook_flags:        CAP_CAPABILITY_HANDLE | CAP_API_INDEX | (1 << 16),
    provides:          "semantic-facts@csharp/v1",
    requires:          "parse.call-sites@cs/v1\nparse.retrieval@cs/v1",
    optional_requires: "",
    file_globs:        "**/*.cs",
    activates_on:      "",
    activation_events: "",
}

// ── Capability handle export ───────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
fn derive_semantic_facts(src: &[u8]) -> Result<Vec<u8>, i64> {
    let call_sites_raw = invoke_parse_call_sites(src).map_err(|_| -1003)?;
    let retrieval_raw = invoke_parse_retrieval(src).map_err(|_| -1003)?;

    let call_sites = decode_call_sites(&call_sites_raw);
    let retrieval = decode_retrieval(&retrieval_raw);

    let mut facts: Vec<SemanticFact> = Vec::new();
    derive_declarations(&retrieval, &mut facts);
    derive_call_edges(&call_sites, &retrieval, &mut facts);
    derive_usings(src, &mut facts);
    derive_awaits(src, &mut facts);
    // C# specific relationships could be added here (Inheritance etc)

    Ok(serialize_facts(&facts))
}

// ── Parser capability invocations ──────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
fn invoke_parse_call_sites(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&16384u32.to_le_bytes());
    invoke_capability("parse.call-sites@cs/v1", &request).map_err(|_| -1003)
}

#[cfg(target_arch = "wasm32")]
fn invoke_parse_retrieval(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&8192u32.to_le_bytes());
    invoke_capability("parse.retrieval@cs/v1", &request).map_err(|_| -1003)
}

// ── Parser response decoding ───────────────────────────────────────────────

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
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

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
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

/// Scope entries (namespace / type) derived from retrieval chunk spans.
/// Used to build `scope::Qualified::names` without an AST.
fn scope_stack_for_offset(
    scopes: &[(u32, u32, alloc::string::String)],
    offset: u32,
    self_start: u32,
    self_len: u32,
    self_name: &str,
) -> Vec<alloc::string::String> {
    let mut chain: Vec<(u32, alloc::string::String)> = Vec::new();
    for (start, end, name) in scopes {
        // Exclude the chunk itself (its own entry contains its own offset).
        if *start == self_start && *end == self_len && name == self_name {
            continue;
        }
        if *start <= offset && offset < start.saturating_add(*end) && !name.is_empty() {
            chain.push((end.saturating_sub(*start), name.clone()));
        }
    }
    // Outermost first (widest span first).
    chain.sort_by(|a, b| b.0.cmp(&a.0));
    chain.into_iter().map(|(_, n)| n).collect()
}

/// Collect namespace/type/interface chunks as scope entries.
fn collect_scopes(retrieval: &[(u32, u32, &str, u8)]) -> Vec<(u32, u32, alloc::string::String)> {
    let mut scopes = Vec::new();
    for &(offset, length, label, kind) in retrieval {
        let name = match kind {
            1 => label.strip_prefix("namespace ").unwrap_or(label),
            2 => label
                .strip_prefix("type ")
                .or_else(|| label.strip_prefix("class "))
                .or_else(|| label.strip_prefix("struct "))
                .or_else(|| label.strip_prefix("enum "))
                .unwrap_or(label),
            7 => label.strip_prefix("interface ").unwrap_or(label),
            _ => continue,
        };
        let name = name.trim();
        if !name.is_empty() && length > 0 {
            scopes.push((offset, length, name.to_string()));
        }
    }
    scopes
}

fn derive_declarations(retrieval: &[(u32, u32, &str, u8)], facts: &mut Vec<SemanticFact>) {
    let scopes = collect_scopes(retrieval);
    for &(offset, length, label, kind) in retrieval {
        match kind {
            1 => { // module (namespace)
                let name = label.strip_prefix("namespace ").unwrap_or(label);
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Module,
                    offset, length, name: name.to_string(), qualified_name: Some(name.to_string()),
                });
            }
            2 => { // type
                let name = label.strip_prefix("type ").or_else(|| label.strip_prefix("class ")).or_else(|| label.strip_prefix("struct ")).or_else(|| label.strip_prefix("enum ")).unwrap_or(label);
                let scope = scope_stack_for_offset(&scopes, offset, offset, length, name);
                let qualified = if scope.is_empty() {
                    None
                } else {
                    let mut q = scope.join("::");
                    q.push_str("::");
                    q.push_str(name);
                    Some(q)
                };
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Type,
                    offset, length, name: name.to_string(), qualified_name: qualified,
                });
            }
            3 => { // function (method)
                let name = label.strip_prefix("function ").unwrap_or(label);
                let scope = scope_stack_for_offset(&scopes, offset, offset, length, name);
                let qualified = if scope.is_empty() {
                    None
                } else {
                    let mut q = scope.join("::");
                    q.push_str("::");
                    q.push_str(name);
                    Some(q)
                };
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Function,
                    offset, length, name: name.to_string(), qualified_name: qualified,
                });
            }
            7 => { // interface
                let name = label.strip_prefix("interface ").unwrap_or(label);
                let scope = scope_stack_for_offset(&scopes, offset, offset, length, name);
                let qualified = if scope.is_empty() {
                    None
                } else {
                    let mut q = scope.join("::");
                    q.push_str("::");
                    q.push_str(name);
                    Some(q)
                };
                facts.push(SemanticFact::DeclareSymbol {
                    kind: SymbolKind::Interface,
                    offset, length, name: name.to_string(), qualified_name: qualified,
                });
            }
            _ => {}
        }
    }
}

fn derive_call_edges(
    call_sites: &[(u32, &str)],
    retrieval: &[(u32, u32, &str, u8)],
    facts: &mut Vec<SemanticFact>,
) {
    let scopes = collect_scopes(retrieval);
    for &(offset, callee) in call_sites {
        // `this.Foo()` inside `Ns.Type` → `Ns.Type::Foo` for exact matching.
        // `base.` receivers and unknown receivers stay bare so core falls
        // back to same-file matching instead of a false exact edge.
        let resolved = if let Some(rest) = callee.strip_prefix("this.") {
            let scope = scope_stack_for_offset(&scopes, offset, offset, u32::MAX, "");
            if scope.is_empty() {
                rest.to_string()
            } else {
                let mut q = scope.join("::");
                q.push_str("::");
                q.push_str(rest);
                q
            }
        } else if let Some(rest) = callee.strip_prefix("base.") {
            rest.to_string()
        } else {
            callee.to_string()
        };
        facts.push(SemanticFact::Calls {
            caller_offset: offset,
            caller_length: callee.len() as u32,
            callee: resolved.clone(),
        });
        if let Some(io_kind) = classify_io(&resolved) {
            facts.push(SemanticFact::IOOperation {
                io_kind,
                offset,
                length: callee.len() as u32,
                descriptor: Some(resolved),
            });
        }
    }
}

/// C#-specific I/O classification over callee names. Lives here (not core):
/// the signals are ecosystem knowledge (`HttpClient` vs `reqwest`).
fn classify_io(callee: &str) -> Option<basalt_plugin_sdk::facts::IOKind> {
    // Compare against the bare tail: `System.Net.Http.HttpClient::GetAsync`
    // and `client.GetAsync` must both hit.
    let tail = callee.rsplit("::").next().unwrap_or(callee);
    let tail = tail.rsplit('.').next().unwrap_or(tail);
    let lower = tail.to_ascii_lowercase();
    let full_lower = callee.to_ascii_lowercase();

    if full_lower.contains("httpclient")
        || full_lower.contains("httprequest")
        || full_lower.contains("webrequest")
        || full_lower.contains("tcpclient")
        || full_lower.contains("udpsocket")
        || full_lower.contains("socket")
        || full_lower.contains("restsharp")
        || ["getasync", "postasync", "putasync", "deleteasync", "sendasync"]
            .contains(&lower.as_str())
    {
        Some(basalt_plugin_sdk::facts::IOKind::Network)
    } else if full_lower.contains("streamreader")
        || full_lower.contains("readalltext")
        || full_lower.contains("readalllines")
        || full_lower.contains("file.read")
        || lower == "read"
        || lower == "openread"
    {
        Some(basalt_plugin_sdk::facts::IOKind::FileRead)
    } else if full_lower.contains("streamwriter")
        || full_lower.contains("writealltext")
        || full_lower.contains("writealllines")
        || full_lower.contains("file.write")
        || full_lower.contains("file.append")
    {
        Some(basalt_plugin_sdk::facts::IOKind::FileWrite)
    } else if full_lower.contains("console.")
        || full_lower.contains("debug.write")
        || full_lower.contains("trace.write")
        || lower == "writeline"
        || lower == "write"
    {
        // `Write` alone is ambiguous — only treat it as StdIO when it
        // wasn't already claimed by FileWrite above.
        Some(basalt_plugin_sdk::facts::IOKind::StdIO)
    } else {
        None
    }
}

/// Extract `await` expressions into `AsyncBoundary` facts via text scan.
/// No AST needed: `await` is a contextual keyword, matched with word
/// boundaries outside of line comments.
fn derive_awaits(src: &[u8], facts: &mut Vec<SemanticFact>) {
    let text = alloc::string::String::from_utf8_lossy(src);
    for line in text.lines() {
        let code = line.split("//").next().unwrap_or("");
        let mut search = code;
        let mut col = 0usize;
        while let Some(pos) = search.find("await") {
            let abs = col + pos;
            let before_ok = abs == 0
                || !code.as_bytes()[abs - 1].is_ascii_alphanumeric() && code.as_bytes()[abs - 1] != b'_';
            let after = abs + 5;
            let after_ok = code.len() <= after
                || (!code.as_bytes()[after].is_ascii_alphanumeric() && code.as_bytes()[after] != b'_');
            if before_ok && after_ok {
                let line_off = line.as_ptr() as usize - text.as_ptr() as usize;
                facts.push(SemanticFact::AsyncBoundary {
                    boundary_kind: basalt_plugin_sdk::facts::AsyncBoundaryKind::Await,
                    offset: (line_off + abs) as u32,
                    length: 5,
                });
            }
            search = &code[after..];
            col = after;
        }
    }
}
/// Handles `using Foo.Bar;`, `using static Foo.Bar;` (skipped — no type
/// scope), and `using Alias = Foo.Bar;` (alias preserved for core's
/// import-alias resolution).
fn derive_usings(src: &[u8], facts: &mut Vec<SemanticFact>) {
    let text = alloc::string::String::from_utf8_lossy(src);
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("using ") else {
            continue;
        };
        if rest.starts_with("static ") {
            continue;
        }
        let end = rest.find(';').unwrap_or(rest.len());
        let directive = rest[..end].trim();
        if directive.is_empty() || !directive.contains('.') && directive.contains('(') {
            continue;
        }
        let (module_path, alias) = match directive.find(" = ") {
            Some(pos) => {
                let a = directive[..pos].trim();
                let p = directive[pos + 3..].trim();
                if a.is_empty() || p.is_empty() {
                    continue;
                }
                (p.to_string(), Some(a.to_string()))
            }
            None => (directive.to_string(), None),
        };
        let offset = line.as_ptr() as usize - text.as_ptr() as usize;
        facts.push(SemanticFact::ImportModule {
            offset: offset as u32,
            length: line.len() as u32,
            module_path,
            alias,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    // namespace App (0..200), class Store (10..150), method Save (30..80).
    fn retrieval_fixture() -> Vec<(u32, u32, &'static str, u8)> {
        vec![
            (0, 200, "namespace App", 1),
            (10, 140, "class Store", 2),
            (30, 50, "function Save", 3),
            (100, 30, "function Load", 3),
        ]
    }

    #[test]
    fn methods_carry_scope_qualified_names() {
        let ret = retrieval_fixture();
        let mut facts = Vec::new();
        derive_declarations(&ret, &mut facts);
        let q = facts.iter().find_map(|f| match f {
            SemanticFact::DeclareSymbol { name, qualified_name, .. } if name == "Save" => {
                Some(qualified_name.clone())
            }
            _ => None,
        }).flatten();
        assert_eq!(q, Some("App::Store::Save".to_string()));
        // The type itself must not include itself in its own scope.
        let qt = facts.iter().find_map(|f| match f {
            SemanticFact::DeclareSymbol { name, qualified_name, .. } if name == "Store" => {
                Some(qualified_name.clone())
            }
            _ => None,
        }).flatten();
        assert_eq!(qt, Some("App::Store".to_string()));
    }

    #[test]
    fn this_receiver_resolves_to_enclosing_type() {
        let ret = retrieval_fixture();
        let sites = vec![(40u32, "this.Save")];
        let mut facts = Vec::new();
        derive_call_edges(&sites, &ret, &mut facts);
        assert!(facts.iter().any(|f| matches!(f,
            SemanticFact::Calls { callee, .. } if callee == "App::Store::Save")));
    }

    #[test]
    fn base_receiver_stays_bare() {
        let ret = retrieval_fixture();
        let sites = vec![(40u32, "base.Dispose")];
        let mut facts = Vec::new();
        derive_call_edges(&sites, &ret, &mut facts);
        assert!(facts.iter().any(|f| matches!(f,
            SemanticFact::Calls { callee, .. } if callee == "Dispose")));
    }

    #[test]
    fn usings_emit_import_facts_with_alias() {        let src = b"using System.Text;\nusing IO = System.IO;\nusing static System.Math;\nnamespace App {}\n";
        let mut facts = Vec::new();
        derive_usings(src, &mut facts);
        assert!(facts.iter().any(|f| matches!(f,
            SemanticFact::ImportModule { module_path, alias: None, .. } if module_path == "System.Text")));
        assert!(facts.iter().any(|f| matches!(f,
            SemanticFact::ImportModule { module_path, alias: Some(a), .. }
                if module_path == "System.IO" && a == "IO")));
        assert!(!facts.iter().any(|f| matches!(f,
            SemanticFact::ImportModule { module_path, .. } if module_path.contains("Math"))));
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use basalt_plugin_sdk::facts::IOKind;

    #[test]
    fn io_classification_hits_csharp_signals() {
        let ret: Vec<(u32, u32, &str, u8)> = vec![];
        let sites = vec![
            (0u32, "HttpClient.GetAsync"),
            (10u32, "File.ReadAllText"),
            (20u32, "StreamWriter.Write"),
            (30u32, "Console.WriteLine"),
            (40u32, "Save"),
        ];
        let mut facts = Vec::new();
        derive_call_edges(&sites, &ret, &mut facts);
        let kinds: Vec<IOKind> = facts
            .iter()
            .filter_map(|f| match f {
                SemanticFact::IOOperation { io_kind, .. } => Some(*io_kind),
                _ => None,
            })
            .collect();
        assert!(kinds.contains(&IOKind::Network), "HttpClient must be Network");
        assert!(kinds.contains(&IOKind::FileRead), "ReadAllText must be FileRead");
        assert!(kinds.contains(&IOKind::FileWrite), "StreamWriter must be FileWrite");
        assert!(kinds.contains(&IOKind::StdIO), "Console must be StdIO");
        assert_eq!(kinds.len(), 4, "Save must not classify");
    }

    #[test]
    fn awaits_detected_with_word_boundaries() {
        let src = b"var x = await FetchAsync();\n// await in comment\nvar awaiting = 1;\n";
        let mut facts = Vec::new();
        derive_awaits(src, &mut facts);
        assert_eq!(facts.len(), 1, "only the real await, not comment/awaiting");
    }
}
