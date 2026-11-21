use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPattern, CallExpression, Expression, ImportDeclarationSpecifier, JSXElement,
    JSXFragment, PropertyKey, Statement,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub const MAX_AST_INSPECT_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiModuleKind {
    React,
    Preact,
    JsxRuntime,
}

#[derive(Debug, Default)]
struct UiBindings {
    namespace_modules: HashMap<String, UiModuleKind>,
    direct_ui_fns: HashSet<String>,
}

fn classify_ui_module(spec: &str) -> Option<UiModuleKind> {
    match spec {
        "react" | "inferno" | "inferno-compat" => Some(UiModuleKind::React),
        "preact" | "preact/compat" => Some(UiModuleKind::Preact),
        "react/jsx-runtime"
        | "react/jsx-dev-runtime"
        | "preact/jsx-runtime"
        | "preact/jsx-dev-runtime"
        | "@emotion/react/jsx-runtime"
        | "@emotion/react/jsx-dev-runtime" => Some(UiModuleKind::JsxRuntime),
        _ => None,
    }
}

fn is_factory_for_module(kind: UiModuleKind, name: &str) -> bool {
    match kind {
        UiModuleKind::React => matches!(name, "createElement" | "cloneElement"),
        UiModuleKind::Preact => matches!(name, "createElement" | "cloneElement" | "h"),
        UiModuleKind::JsxRuntime => matches!(name, "jsx" | "jsxs" | "jsxDEV" | "jsxsDEV"),
    }
}

fn collect_ui_bindings(program: &oxc_ast::ast::Program<'_>) -> UiBindings {
    // INVARIANT: Track each namespace binding's exact source module (`React`, `Preact`, `JsxRuntime`) and apply one unified `is_factory_for_module` table across named imports, namespace member calls (`Preact.h`, `React.createElement`), `require(...)`, and destructuring.
    let mut b = UiBindings::default();
    b.namespace_modules
        .insert("React".to_string(), UiModuleKind::React);

    for stmt in &program.body {
        match stmt {
            Statement::ImportDeclaration(decl) => {
                let Some(kind) = classify_ui_module(decl.source.value.as_str()) else {
                    continue;
                };
                if let Some(specs) = &decl.specifiers {
                    for sp in specs {
                        match sp {
                            ImportDeclarationSpecifier::ImportDefaultSpecifier(d) => {
                                b.namespace_modules
                                    .insert(d.local.name.as_str().to_string(), kind);
                            }
                            ImportDeclarationSpecifier::ImportNamespaceSpecifier(n) => {
                                b.namespace_modules
                                    .insert(n.local.name.as_str().to_string(), kind);
                            }
                            ImportDeclarationSpecifier::ImportSpecifier(named) => {
                                let imported = named.imported.name().as_str();
                                let local = named.local.name.as_str().to_string();
                                if is_factory_for_module(kind, imported) {
                                    b.direct_ui_fns.insert(local);
                                }
                            }
                        }
                    }
                }
            }
            Statement::VariableDeclaration(vdecl) => {
                for d in &vdecl.declarations {
                    let Some(init) = &d.init else { continue };
                    let req_mod: Option<&str> = match init {
                        Expression::CallExpression(call) => {
                            let is_req = matches!(
                                &call.callee,
                                Expression::Identifier(id) if id.name.as_str() == "require"
                            );
                            if is_req {
                                call.arguments.first().and_then(|arg| match arg.as_expression() {
                                    Some(Expression::StringLiteral(s)) => Some(s.value.as_str()),
                                    _ => None,
                                })
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    let kind = if let Some(m) = req_mod {
                        classify_ui_module(m)
                    } else if let Expression::Identifier(id) = init {
                        b.namespace_modules.get(id.name.as_str()).copied()
                    } else {
                        None
                    };
                    let Some(kind) = kind else {
                        continue;
                    };
                    match &d.id {
                        BindingPattern::BindingIdentifier(id) if req_mod.is_some() => {
                            b.namespace_modules
                                .insert(id.name.as_str().to_string(), kind);
                        }
                        BindingPattern::ObjectPattern(obj) => {
                            for prop in &obj.properties {
                                let key_name = match &prop.key {
                                    PropertyKey::StaticIdentifier(id) => id.name.as_str(),
                                    PropertyKey::StringLiteral(s) => s.value.as_str(),
                                    _ => continue,
                                };
                                let local_name = match &prop.value {
                                    BindingPattern::BindingIdentifier(id) => id.name.as_str(),
                                    _ => continue,
                                };
                                if is_factory_for_module(kind, key_name) {
                                    b.direct_ui_fns.insert(local_name.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    b
}

struct VisualUiFinder {
    bindings: UiBindings,
    jsx_spans: Vec<Span>,
    ui_call_spans: Vec<Span>,
}

impl VisualUiFinder {
    fn new(bindings: UiBindings) -> Self {
        Self {
            bindings,
            jsx_spans: Vec::new(),
            ui_call_spans: Vec::new(),
        }
    }

    fn call_is_visual_ui(&self, call: &CallExpression<'_>) -> bool {
        match &call.callee {
            Expression::Identifier(id) => self.bindings.direct_ui_fns.contains(id.name.as_str()),
            Expression::StaticMemberExpression(mem) => {
                let prop = mem.property.name.as_str();
                if let Expression::Identifier(obj) = &mem.object {
                    if let Some(&kind) = self.bindings.namespace_modules.get(obj.name.as_str()) {
                        return is_factory_for_module(kind, prop);
                    }
                }
                false
            }
            _ => false,
        }
    }
}

impl<'a> Visit<'a> for VisualUiFinder {
    fn visit_jsx_element(&mut self, it: &JSXElement<'a>) {
        self.jsx_spans.push(it.span);
        walk::walk_jsx_element(self, it);
    }

    fn visit_jsx_fragment(&mut self, it: &JSXFragment<'a>) {
        self.jsx_spans.push(it.span);
        walk::walk_jsx_fragment(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if self.call_is_visual_ui(it) {
            self.ui_call_spans.push(it.span);
        }
        walk::walk_call_expression(self, it);
    }
}

fn parse_visual_spans(src: &str, is_typescript: bool) -> (Vec<Span>, Vec<Span>, bool) {
    let allocator = Allocator::default();
    let source_type = if is_typescript {
        SourceType::tsx()
    } else {
        SourceType::jsx()
    };
    let ret = Parser::new(&allocator, src, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();
    let bindings = collect_ui_bindings(&ret.program);
    let mut finder = VisualUiFinder::new(bindings);
    finder.visit_program(&ret.program);
    let clean = !ret.panicked && ret.errors.is_empty();
    (finder.jsx_spans, finder.ui_call_spans, clean)
}

/// Strict JSX AST predicate (`JSXElement` / `JSXFragment` only).
/// Returns `Some(true)` if JSX is present, `Some(false)` if parsed cleanly with no JSX, `None` on parse error without JSX.
pub fn source_has_jsx_checked(src: &str, is_typescript: bool) -> Option<bool> {
    if !src.contains('<') {
        return Some(false);
    }
    let (jsx_spans, _, clean) = parse_visual_spans(src, is_typescript);
    if !jsx_spans.is_empty() {
        return Some(true);
    }
    if !clean {
        return None;
    }
    Some(false)
}

/// Visual UI AST predicate for `.tsx`/`.jsx`: detects BOTH JSX (`JSXElement`/`JSXFragment`) AND React / `react/jsx-runtime` / Preact element creation calls (`React.createElement`, imported `createElement`/`cloneElement`/`jsx`/`jsxs`/`jsxDEV`/`h`).
pub fn source_has_visual_ui_checked(src: &str, is_typescript: bool) -> Option<bool> {
    if !src.contains('<')
        && !src.contains("createElement")
        && !src.contains("cloneElement")
        && !src.contains("jsx")
        && !src.contains("preact")
    {
        return Some(false);
    }
    let (jsx_spans, ui_call_spans, clean) = parse_visual_spans(src, is_typescript);
    if !jsx_spans.is_empty() || !ui_call_spans.is_empty() {
        return Some(true);
    }
    if !clean {
        return None;
    }
    Some(false)
}

pub fn tsx_source_has_jsx(src: &str) -> bool {
    source_has_jsx_checked(src, true).unwrap_or(false)
}

pub fn file_has_visual_ui(raw_path: &str) -> Option<bool> {
    let p = Path::new(raw_path);
    let meta = fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MAX_AST_INSPECT_BYTES {
        return None;
    }
    let text = fs::read_to_string(p).ok()?;
    let is_ts = p
        .extension()
        .and_then(|e| e.to_str())
        .map_or(true, |e| e.eq_ignore_ascii_case("tsx") || e.eq_ignore_ascii_case("ts"));
    source_has_visual_ui_checked(&text, is_ts)
}

/// Full-file pre-edit AST check for `PreToolUse` on `.tsx`/`.jsx`:
/// - For full overwrites (`replaced_targets.is_empty()`), returns `true` iff the existing file contains any visual UI AST node (JSX or React/`jsx-runtime` element creation).
/// - For targeted edits (`edit_file`, `replace_file_content`, `multi_replace_file_content`), parses the ENTIRE pre-edit file and returns `true` iff ANY visual UI AST node's byte `Span` overlaps ANY replaced target occurrence (handling unbalanced fragments accurately and rejecting JSX-like strings inside template literals/comments!).
pub fn pre_edit_file_touches_visual_ui(raw_path: &str, replaced_targets: &[&str]) -> bool {
    let p = Path::new(raw_path);
    let Ok(meta) = fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() || meta.len() > MAX_AST_INSPECT_BYTES {
        return false;
    }
    let Ok(raw_text) = fs::read_to_string(p) else {
        return false;
    };
    let is_ts = p
        .extension()
        .and_then(|e| e.to_str())
        .map_or(true, |e| e.eq_ignore_ascii_case("tsx") || e.eq_ignore_ascii_case("ts"));
    let norm_src = raw_text.replace("\r\n", "\n");
    let (jsx_spans, ui_call_spans, _clean) = parse_visual_spans(&norm_src, is_ts);
    if jsx_spans.is_empty() && ui_call_spans.is_empty() {
        return false;
    }
    if replaced_targets.is_empty() {
        return true;
    }
    let all_spans: Vec<(usize, usize)> = jsx_spans
        .into_iter()
        .chain(ui_call_spans)
        .map(|s| (s.start as usize, s.end as usize))
        .collect();
    for raw_target in replaced_targets {
        let norm_t = raw_target.replace("\r\n", "\n");
        if norm_t.is_empty() {
            continue;
        }
        for (start, matched) in norm_src.match_indices(&norm_t) {
            let end = start + matched.len();
            if all_spans.iter().any(|&(ns, ne)| ns < end && start < ne) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oxc_ast_jsx_and_react_create_element_matrix() {
        // 1. Real JSX components, fragments, generic JSX components, ASI, multiline & mixed files -> true
        assert_eq!(source_has_jsx_checked("export const L = ({ items }: any) => <List<User> items={items} />;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const T = () => <Table<Record<string, User[]>> />;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const U = () => <_Button />;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const D = () => <$Icon size={16} />;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const F = () => <><span>ok</span></>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const Label = () => <p>Don't stop</p>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const Note = () => <p>(note): Don't stop</p>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const Msg = ({ ok }: any) => <div>{ok ? \"can't\" : 'won\\'t'} Don't stop</div>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const Nested = ({ items }: any) => <Card>Don't forget {items.map((x: any) => <span>Can't</span>)}</Card>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("export type Props = { x: string }\nexport const AfterType = () => <p>Don't stop</p>;", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Props = { label: string }\nroot.render(<App />)", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Props = { label: string }\n// mount app\nroot.render(<App />)", true), Some(true));
        assert_eq!(source_has_jsx_checked("export type Lit = <T>(x: \"</T> \") => T\nroot.render(<App />)", true), Some(true));
        assert_eq!(source_has_jsx_checked("type A = string\n(<p>Don't stop</p>)", true), Some(true));
        assert_eq!(source_has_jsx_checked("type A = Record<string, string>\nrender(<p>Don't stop</p>)", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Tpl = `a${`b`}c`\nroot.render(<App />)", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Props = { label: string }\n[1, 2].map((n) => <li key={n}>{n}</li>)", true), Some(true));
        assert_eq!(source_has_jsx_checked("class W { type\n  el = <App />\n}", true), Some(true));
        assert_eq!(source_has_jsx_checked("class W { interface\n  el = <App />\n}", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Props = object /*\n*/export const View = () => <div />", true), Some(true));
        assert_eq!(source_has_jsx_checked("class W { type /*\n*/ el = <App />\n}", true), Some(true));
        assert_eq!(source_has_jsx_checked("type Props = object /*\r*/export const View = () => <div />", true), Some(true));
        assert_eq!(source_has_jsx_checked("export const JsxComp = () => <main><Slot /></main>;", false), Some(true));

        // 2. Pure TypeScript / JS logic, generics, type aliases, interfaces, regexes, strings, templates, comments -> false
        assert_eq!(source_has_jsx_checked("type /* ok */ Lit = <T>(x: \"</T> \") => T", true), Some(false));
        assert_eq!(source_has_jsx_checked("type Multi = { a: string } /*\n*/ | (<T>(x: \"</T> \") => T)", true), Some(false));
        assert_eq!(source_has_jsx_checked(r#"export const html = "<div>hello</div>";"#, true), Some(false));
        assert_eq!(source_has_jsx_checked("export const tpl = (x: string) => `<span>${x}</span>`;", true), Some(false));
        assert_eq!(source_has_jsx_checked("export type Mapper = <T>(value: T) => T;", true), Some(false));
        assert_eq!(source_has_jsx_checked(r#"export type Mapper = <T>(value: T) => T; const s = "</T>";"#, true), Some(false));
        assert_eq!(source_has_jsx_checked("export type MultilineFn = <T>(\n  x: \"</T> \"\n) =>\n  T", true), Some(false));
        assert_eq!(source_has_jsx_checked("export type MultilineUnion =\n  | (<T>(x: \"</T> \") => T)\n  | (<U>(y: \"</U> \") => U)", true), Some(false));
        assert_eq!(source_has_jsx_checked("export type MultilineCond<T> = T extends string\n  ? (<U>(x: \"</U> \") => U)\n  : never;", true), Some(false));
        assert_eq!(source_has_jsx_checked(r#"export const fnAnn: <T>(x: "</T> ") => T = (x) => x;"#, true), Some(false));
        assert_eq!(source_has_jsx_checked("export const fnTpl: <T>(x: `</T>\n`) => T = (x) => x;", true), Some(false));
        assert_eq!(source_has_jsx_checked("export interface Fn { map: <T>(value: T) => T; }", true), Some(false));
        assert_eq!(source_has_jsx_checked("export const id = <T,>(x: T): T => x;", true), Some(false));
        assert_eq!(source_has_jsx_checked("export const pick = <T extends object>(x: T): Array<T> => [x];", true), Some(false));
        assert_eq!(source_has_jsx_checked("export const rx = (x: number) => x < /abc/.source.length;", true), Some(false));
        assert_eq!(source_has_jsx_checked("// <div /> commented out\nexport const cmp = (a: number, b: number) => a < b && b > 0;", true), Some(false));

        // 3. Broken/unparseable TSX fails closed (`None`).
        assert_eq!(source_has_jsx_checked("export const Broken = (<div className={", true), None);

        // 4. React.createElement / react/jsx-runtime AST calls: detected by `source_has_visual_ui_checked`, while strict JSX stays false and unrelated local `createElement` stays false!
        let react_ce = "import React from 'react';\nexport const Badge = () => React.createElement('span', { className: 'badge' }, 'New');";
        assert_eq!(source_has_jsx_checked(react_ce, true), Some(false));
        assert_eq!(source_has_visual_ui_checked(react_ce, true), Some(true));

        let named_ce = "import { createElement as h } from 'react';\nexport const Btn = () => h('button', null, 'Save');";
        assert_eq!(source_has_visual_ui_checked(named_ce, true), Some(true));

        let jsx_rt = "import { jsx as _jsx } from 'react/jsx-runtime';\nexport const Card = () => _jsx('div', { children: 'ok' });";
        assert_eq!(source_has_visual_ui_checked(jsx_rt, true), Some(true));

        let preact_ns = "import * as Preact from 'preact';\nexport const Chip = () => Preact.h('span', null, 'tag');";
        assert_eq!(source_has_visual_ui_checked(preact_ns, true), Some(true));

        let preact_destr = "import * as Preact from 'preact';\nconst { h } = Preact;\nexport const Chip = () => h('span', null, 'tag');";
        assert_eq!(source_has_visual_ui_checked(preact_destr, true), Some(true));

        let local_ce = "function createElement(tag: string) { return tag; }\nexport const x = createElement('div');";
        assert_eq!(source_has_visual_ui_checked(local_ce, true), Some(false));

        // 5. Full-file pre-edit AST span overlap: unbalanced fragment touching `<Panel />` returns true; template-literal `<Panel />` returns false!
        let td = std::env::temp_dir().join(format!("carbon-tsx-ast-{}", std::process::id()));
        let _ = fs::remove_dir_all(&td);
        fs::create_dir_all(&td).unwrap();

        let comp_p = td.join("Panel.tsx");
        fs::write(&comp_p, "export function App() {\r\n  return <Panel />;\r\n}\r\n").unwrap();
        assert!(
            pre_edit_file_touches_visual_ui(&comp_p.to_string_lossy(), &["  return <Panel />;\n}"]),
            "unbalanced Target overlapping real JSXElement AST node must return true"
        );
        assert!(
            pre_edit_file_touches_visual_ui(&comp_p.to_string_lossy(), &[]),
            "full write_file overwrite of visual file must return true"
        );

        let tpl_p = td.join("Docs.tsx");
        fs::write(&tpl_p, "export const example = `<Panel />`;\n").unwrap();
        assert!(
            !pre_edit_file_touches_visual_ui(&tpl_p.to_string_lossy(), &["<Panel />"]),
            "replacing <Panel /> inside a template literal string must NOT falsely flag visual UI"
        );
        let _ = fs::remove_dir_all(&td);
    }
}
