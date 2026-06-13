//! Extract command - Extract complete module info from a file
//!
//! Returns functions, classes, imports, and call graph for a single file.
//! Auto-routes through daemon when available for ~35x speedup.
//!
//! When any of `--function` / `--method` / `--class` is set, the command
//! instead computes directly (bypassing the daemon, which returns a plain
//! `ModuleInfo` with no source spans) and emits a compact, code-first
//! `FilteredExtract` — porting `api.py:extract_file_with_code`.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::{FunctionInfo, ModuleInfo};
use tldr_core::{extract_file_with_lang, Language};

use crate::commands::daemon_router::{params_with_file_lang, try_daemon_route};
use crate::output::{
    format_filtered_extract_text, format_module_info_text, FilteredClass, FilteredExtract,
    FilteredFn, OutputFormat, OutputWriter,
};

/// Extract complete module info from a file
#[derive(Debug, Args)]
pub struct ExtractArgs {
    /// File to extract
    pub file: PathBuf,

    /// Programming language (auto-detected from file extension if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Filter to a specific class (compact, code-first output)
    #[arg(long = "class")]
    pub filter_class: Option<String>,

    /// Filter to a specific top-level function (compact, code-first output)
    #[arg(long = "function")]
    pub filter_function: Option<String>,

    /// Filter to a specific method, given as `Class.method` (compact output)
    #[arg(long = "method")]
    pub filter_method: Option<String>,
}

impl ExtractArgs {
    /// Run the extract command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // cross-command-consistency-v3 (P5.BUG-N1): resolve the language hint
        // BEFORE choosing a route. The user's explicit `--lang` wins over any
        // detection. When the user did not pass `--lang`, apply the
        // sibling-aware widening so `.h` files in C++ projects parse as C++
        // (otherwise the C grammar mis-classifies `class Foo` as a function
        // with `return_type: "class"` and emits zero classes).
        let resolved_lang: Option<Language> = match self.lang {
            Some(l) => Some(l),
            None => Language::from_path_with_siblings(&self.file),
        };

        // Filtered extract: bypass the daemon (which returns a plain
        // ModuleInfo with no `code` span) and compute the compact,
        // code-first result directly. Mirrors cli.py:1008-1018.
        if self.filter_class.is_some()
            || self.filter_function.is_some()
            || self.filter_method.is_some()
        {
            writer.progress(&format!(
                "Extracting filtered symbols from {}...",
                self.file.display()
            ));
            let module = extract_file_with_lang(&self.file, None, resolved_lang)?;
            let source = std::fs::read_to_string(&self.file).unwrap_or_default();
            let result = build_filtered_extract(
                &module,
                &source,
                self.filter_function.as_deref(),
                self.filter_method.as_deref(),
                self.filter_class.as_deref(),
            );
            if writer.is_text() {
                writer.write_text(&format_filtered_extract_text(&result))?;
            } else {
                writer.write(&result)?;
            }
            return Ok(());
        }

        // Try daemon first for cached result (use file's parent as project root)
        let project = self.file.parent().unwrap_or(&self.file);
        if let Some(result) = try_daemon_route::<ModuleInfo>(
            project,
            "extract",
            params_with_file_lang(&self.file, resolved_lang.as_ref().map(|l| l.as_str())),
        ) {
            self.emit_bare(&writer, &result)?;
            return Ok(());
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Extracting module info from {}...",
            self.file.display()
        ));

        // Extract module info, propagating the resolved language hint so the
        // parser pool honors it instead of falling back to extension-based
        // detection (which breaks `.h` for C++ and any extensionless file
        // with `--lang`).
        let result = extract_file_with_lang(&self.file, None, resolved_lang)?;
        self.emit_bare(&writer, &result)?;

        Ok(())
    }

    /// Emit a bare (unfiltered) extract: the full `ModuleInfo`, plus a 2-line
    /// stderr advisory when the file dumps more than 5 symbols (functions +
    /// methods + classes). Ports cli.py:1022-1034. Silent at <= 5 symbols and
    /// suppressed under `--quiet`.
    fn emit_bare(&self, writer: &OutputWriter, result: &ModuleInfo) -> Result<()> {
        let n_symbols = result.functions.len()
            + result
                .classes
                .iter()
                .map(|c| c.methods.len())
                .sum::<usize>()
            + result.classes.len();
        if n_symbols > 5 && !writer.quiet() {
            eprint!(
                "tldr: extract dumped {} symbols' metadata from {}.\n      Pass --function NAME / --method Class.method / --class Name to filter.\n",
                n_symbols,
                self.file.display()
            );
        }

        if writer.is_text() {
            writer.write_text(&format_module_info_text(result))?;
        } else {
            writer.write(result)?;
        }
        Ok(())
    }
}

/// Slice a 1-indexed, inclusive line range out of `source_lines`, returning
/// `None` when the range is unknown or out of bounds.
///
/// Ports `api.py:1918-1925` (`_span`): `None` when `start <= 0`, `end <= 0`,
/// `end < start`, or `start` is past the end of file; otherwise the lines
/// `[start-1 .. min(end, n)]` joined with `\n`.
fn span(source_lines: &[&str], start: u32, end: u32) -> Option<String> {
    if start == 0 || end == 0 || end < start {
        return None;
    }
    let lo = (start - 1) as usize;
    let hi = std::cmp::min(end as usize, source_lines.len());
    if lo >= source_lines.len() {
        return None;
    }
    Some(source_lines[lo..hi].join("\n"))
}

/// Build the compact, code-first filtered extract.
///
/// Ports `api.py:extract_file_with_code` (`api.py:1863-2022`): applies the
/// class / method / function filters (with the `--function`->method fallback
/// and class > method > function precedence), injects a `code` source span on
/// each surviving symbol, and drops `imports` / `call_graph`.
///
/// Parity notes:
/// - A dotless `--method` (e.g. `NoDotHere` or `Class::method`) yields zero
///   classes — Python's `method.split(".", 1)` only narrows when a `.` is
///   present, and we do NOT normalize `::` -> `.` (`api.py:1933-1948`,
///   verification B7/B8).
/// - Class names that don't match yield an empty `classes` list.
fn build_filtered_extract(
    module: &ModuleInfo,
    source: &str,
    function: Option<&str>,
    method: Option<&str>,
    class_: Option<&str>,
) -> FilteredExtract {
    let source_lines: Vec<&str> = source.lines().collect();

    let mk_fn = |f: &FunctionInfo| FilteredFn {
        inner: f.clone(),
        code: span(&source_lines, f.line_number, f.line_end),
    };

    let mut out_classes: Vec<FilteredClass> = Vec::new();
    let mut out_functions: Vec<FilteredFn> = Vec::new();

    // --- Class selection (mirrors api.py:1927-1971) ---
    if let Some(class_name) = class_ {
        // Class filter: keep matching classes with all methods.
        for c in &module.classes {
            if c.name == class_name {
                out_classes.push(FilteredClass {
                    inner: c.clone(),
                    methods: c.methods.iter().map(&mk_fn).collect(),
                    code: span(&source_lines, c.line_number, c.line_end),
                });
            }
        }
    } else if let Some(method_sel) = method {
        // Method filter: split on first '.'. Without a '.' the result is
        // empty (parity — no `::` normalization).
        if let Some((class_name, method_name)) = method_sel.split_once('.') {
            for c in &module.classes {
                if c.name == class_name {
                    let methods: Vec<FilteredFn> = c
                        .methods
                        .iter()
                        .filter(|m| m.name == method_name)
                        .map(&mk_fn)
                        .collect();
                    out_classes.push(FilteredClass {
                        inner: c.clone(),
                        methods,
                        // No class-level code on a method filter
                        // (api.py:2001-2002 injects only method spans).
                        code: None,
                    });
                }
            }
        }
        // else: dotless -> classes stays empty.
    } else if let Some(func_name) = function {
        // Function filter with class-method fallback (api.py:1949-1971):
        // if no top-level function matches, search classes[].methods[].
        let top_level_match = module.functions.iter().any(|f| f.name == func_name);
        if !top_level_match {
            for c in &module.classes {
                let methods: Vec<FilteredFn> = c
                    .methods
                    .iter()
                    .filter(|m| m.name == func_name)
                    .map(&mk_fn)
                    .collect();
                if !methods.is_empty() {
                    out_classes.push(FilteredClass {
                        inner: c.clone(),
                        methods,
                        // Function-fallback never injects class code
                        // (api.py:1986-1993 injects only method spans here).
                        code: None,
                    });
                }
            }
        }
    }

    // --- Top-level function selection (mirrors api.py:1973-1983) ---
    if let Some(func_name) = function {
        out_functions = module
            .functions
            .iter()
            .filter(|f| f.name == func_name)
            .map(&mk_fn)
            .collect();
    }
    // class_ / method clear top-level functions (already empty here).

    FilteredExtract {
        file_path: module.file_path.display().to_string(),
        language: module.language.as_str().to_string(),
        classes: out_classes,
        functions: out_functions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tldr_core::types::{ClassInfo, IntraFileCallGraph, ModuleInfo};

    fn fn_info(name: &str, line: u32, end: u32, is_method: bool) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            params: vec![],
            return_type: None,
            docstring: None,
            is_method,
            is_async: false,
            decorators: vec![],
            line_number: line,
            line_end: end,
        }
    }

    fn class_info(name: &str, line: u32, end: u32, methods: Vec<FunctionInfo>) -> ClassInfo {
        ClassInfo {
            name: name.to_string(),
            bases: vec![],
            docstring: None,
            methods,
            fields: vec![],
            decorators: vec![],
            line_number: line,
            line_end: end,
        }
    }

    // sample source: lines are 1-indexed.
    //  1: def alpha():
    //  2:     return 1
    //  3:
    //  4: class Widget:
    //  5:     def render(self):
    //  6:         return 2
    //  7:     def hide(self):
    //  8:         return 3
    fn sample_source() -> String {
        "def alpha():\n    return 1\n\nclass Widget:\n    def render(self):\n        return 2\n    def hide(self):\n        return 3\n".to_string()
    }

    fn sample_module() -> ModuleInfo {
        ModuleInfo {
            file_path: "/tmp/sample.py".into(),
            language: Language::Python,
            docstring: None,
            imports: vec![],
            functions: vec![fn_info("alpha", 1, 2, false)],
            classes: vec![class_info(
                "Widget",
                4,
                8,
                vec![
                    fn_info("render", 5, 6, true),
                    fn_info("hide", 7, 8, true),
                ],
            )],
            constants: vec![],
            call_graph: IntraFileCallGraph::default(),
        }
    }

    // B1: --function with a top-level match injects code, no classes.
    #[test]
    fn b1_function_top_level_with_code() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), Some("alpha"), None, None);
        assert!(r.classes.is_empty());
        assert_eq!(r.functions.len(), 1);
        assert_eq!(r.functions[0].inner.name, "alpha");
        assert_eq!(
            r.functions[0].code.as_deref(),
            Some("def alpha():\n    return 1")
        );
    }

    // B2: --method narrows to one method with code; class shell retained; no class code.
    #[test]
    fn b2_method_narrowed_with_code() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), None, Some("Widget.render"), None);
        assert!(r.functions.is_empty());
        assert_eq!(r.classes.len(), 1);
        assert_eq!(r.classes[0].inner.name, "Widget");
        assert!(r.classes[0].code.is_none(), "method filter has no class code");
        assert_eq!(r.classes[0].methods.len(), 1);
        assert_eq!(r.classes[0].methods[0].inner.name, "render");
        assert_eq!(
            r.classes[0].methods[0].code.as_deref(),
            Some("    def render(self):\n        return 2")
        );
    }

    // B3: --class returns shell with all methods, code on class and each method.
    #[test]
    fn b3_class_all_methods_with_code() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), None, None, Some("Widget"));
        assert!(r.functions.is_empty());
        assert_eq!(r.classes.len(), 1);
        let c = &r.classes[0];
        assert_eq!(c.methods.len(), 2);
        assert!(c.code.is_some(), "class filter injects class code");
        assert!(c.code.as_ref().unwrap().starts_with("class Widget:"));
        assert!(c.methods.iter().all(|m| m.code.is_some()));
    }

    // B6: --function fallback to class method when no top-level matches.
    #[test]
    fn b6_function_fallback_to_method() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), Some("render"), None, None);
        // No top-level `render`, so functions empty and classes narrowed.
        assert!(r.functions.is_empty());
        assert_eq!(r.classes.len(), 1);
        assert_eq!(r.classes[0].methods.len(), 1);
        assert_eq!(r.classes[0].methods[0].inner.name, "render");
        assert!(r.classes[0].code.is_none());
        assert!(r.classes[0].methods[0].code.is_some());
    }

    // B7: line_end == 0 omits code.
    #[test]
    fn b7_zero_end_omits_code() {
        let mut m = sample_module();
        m.functions[0].line_end = 0;
        let r = build_filtered_extract(&m, &sample_source(), Some("alpha"), None, None);
        assert_eq!(r.functions.len(), 1);
        assert!(r.functions[0].code.is_none());
    }

    // B8: dotless --method yields empty classes (parity, no :: normalization).
    #[test]
    fn b8_dotless_method_empty() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), None, Some("NoDotHere"), None);
        assert!(r.classes.is_empty());
        assert!(r.functions.is_empty());

        // `Widget::render` has no '.', so also empty (NOT normalized).
        let r2 = build_filtered_extract(&m, &sample_source(), None, Some("Widget::render"), None);
        assert!(r2.classes.is_empty());
        assert!(r2.functions.is_empty());
    }

    // Method filter on a non-existent class yields empty classes.
    #[test]
    fn method_unknown_class_empty() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), None, Some("Nope.render"), None);
        assert!(r.classes.is_empty());
    }

    // span(): out-of-range slice returns None; in-range slices the lines.
    #[test]
    fn span_bounds() {
        let lines = vec!["a", "b", "c"];
        assert_eq!(span(&lines, 0, 2), None);
        assert_eq!(span(&lines, 2, 0), None);
        assert_eq!(span(&lines, 3, 2), None); // end < start
        assert_eq!(span(&lines, 5, 6), None); // start past EOF
        assert_eq!(span(&lines, 1, 2).as_deref(), Some("a\nb"));
        // end clamped to len
        assert_eq!(span(&lines, 2, 99).as_deref(), Some("b\nc"));
    }

    // Compact serialization drops imports/call_graph and omits empty arrays.
    #[test]
    fn serialize_compact_shape() {
        let m = sample_module();
        let r = build_filtered_extract(&m, &sample_source(), Some("alpha"), None, None);
        let v = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("file_path"));
        assert!(obj.contains_key("language"));
        assert!(obj.contains_key("functions"));
        assert!(!obj.contains_key("classes"), "empty classes omitted");
        assert!(!obj.contains_key("imports"));
        assert!(!obj.contains_key("call_graph"));
        // code present on the matched function
        let code = v["functions"][0]["code"].as_str().unwrap();
        assert!(code.contains("def alpha():"));
    }
}
