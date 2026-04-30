//! vt=PathTraversal lang=rust — names below are inside strings/comments only
//!
//! Documentation strings only. None of `std::env::var`,
//! `std::process::Command`, `std::fs::File::open`, `reqwest::blocking::get`,
//! or `serde_json::from_str` are invoked below.

pub fn docs_only() -> String {
    let doc = "std::env::var(\"X\") flows into std::process::Command and std::fs::File::open";
    let more = "reqwest::blocking::get and serde_json::from_str — referenced in strings only";
    format!("{} {}", doc, more)
}
