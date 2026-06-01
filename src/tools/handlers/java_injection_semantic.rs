use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolSpec,
    risk::{self, DANGER, NORMAL, WARNING},
};

const DEFAULT_BENCHMARK_SOURCE_ROOT: &str =
    "target/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode";

#[derive(Debug, Clone, Copy)]
pub struct JavaInjectionSemanticScanTool;

#[async_trait]
impl ToolHandler for JavaInjectionSemanticScanTool {
    fn name(&self) -> &'static str {
        "java_injection_semantic_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Statically inspect a Java source file or OWASP Benchmark case for SQL/LDAP/XPath/session-boundary source-to-sink evidence, including request header/parameter taint, helper safe sources, and simple constant overwrite branches.",
            json!({
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "Optional OWASP Benchmark case ID such as BenchmarkTest00008. Used with source_root when source_path is omitted."
                    },
                    "source_path": {
                        "type": "string",
                        "description": "Optional Java source file path to inspect."
                    },
                    "source_root": {
                        "type": "string",
                        "description": "Directory containing OWASP Benchmark Java test case files.",
                        "default": DEFAULT_BENCHMARK_SOURCE_ROOT
                    }
                },
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        let input: JavaInjectionSemanticInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;
        let report = run_scan(input, self.name())?;
        let metadata = serde_json::to_value(&report).map_err(|error| ToolError::Execution {
            tool: self.name().to_owned(),
            message: error.to_string(),
        })?;

        Ok(ToolOutput::text(call.id, report.summary()).with_metadata(metadata))
    }
}

#[derive(Debug, Deserialize)]
struct JavaInjectionSemanticInput {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default = "default_source_root")]
    source_root: String,
}

#[derive(Debug, Serialize)]
struct JavaInjectionSemanticReport {
    source_path: String,
    case_id: Option<String>,
    risk_level: String,
    summary: String,
    findings: Vec<InjectionSemanticFinding>,
    tainted_variables: Vec<String>,
    sinks: Vec<String>,
}

impl JavaInjectionSemanticReport {
    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct InjectionSemanticFinding {
    category: String,
    sink: String,
    risk_level: String,
    evidence: String,
    recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueState {
    Tainted(String),
    Constant(String),
    Unknown,
}

#[derive(Debug, Default)]
struct JavaState {
    strings: HashMap<String, ValueState>,
    ints: HashMap<String, i64>,
}

fn run_scan(
    input: JavaInjectionSemanticInput,
    tool: &str,
) -> Result<JavaInjectionSemanticReport> {
    let source_path = resolve_source_path(&input, tool)?;
    let source = fs::read_to_string(&source_path).map_err(|error| ToolError::Execution {
        tool: tool.to_owned(),
        message: format!("failed to read {}: {error}", source_path.display()),
    })?;
    let analysis = analyze_java_injection_source(&source);
    let risk_level = risk::max_label(
        analysis
            .findings
            .iter()
            .map(|finding| finding.risk_level.as_str()),
    )
    .to_owned();
    let summary = if analysis.findings.is_empty() {
        "Java injection semantic scan completed: no SQL/LDAP sinks found.".to_owned()
    } else {
        let dangerous = analysis
            .findings
            .iter()
            .filter(|finding| finding.risk_level == DANGER)
            .count();
        let normal = analysis
            .findings
            .iter()
            .filter(|finding| finding.risk_level == NORMAL)
            .count();
        let warning = analysis
            .findings
            .iter()
            .filter(|finding| finding.risk_level == WARNING)
            .count();
        format!(
            "Java injection semantic scan completed: {} finding(s), {dangerous} tainted sink(s), {normal} safe sink(s), {warning} uncertain sink(s), overall risk {risk_level}.",
            analysis.findings.len()
        )
    };

    Ok(JavaInjectionSemanticReport {
        source_path: source_path.display().to_string(),
        case_id: input.case_id,
        risk_level,
        summary,
        findings: analysis.findings,
        tainted_variables: analysis.tainted_variables,
        sinks: analysis.sinks,
    })
}

fn resolve_source_path(input: &JavaInjectionSemanticInput, tool: &str) -> Result<PathBuf> {
    if let Some(path) = input
        .source_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        return Ok(PathBuf::from(path));
    }

    let Some(case_id) = input
        .case_id
        .as_deref()
        .map(str::trim)
        .filter(|case_id| !case_id.is_empty())
    else {
        return Err(ToolError::InvalidInput {
            tool: tool.to_owned(),
            message: "provide source_path or case_id".to_owned(),
        });
    };
    if !case_id.starts_with("BenchmarkTest")
        || !case_id["BenchmarkTest".len()..]
            .chars()
            .all(|ch| ch.is_ascii_digit())
    {
        return Err(ToolError::InvalidInput {
            tool: tool.to_owned(),
            message: format!("unsupported case_id: {case_id}"),
        });
    }

    Ok(Path::new(&input.source_root).join(format!("{case_id}.java")))
}

#[derive(Debug)]
struct InjectionAnalysis {
    findings: Vec<InjectionSemanticFinding>,
    tainted_variables: Vec<String>,
    sinks: Vec<String>,
}

fn analyze_java_injection_source(source: &str) -> InjectionAnalysis {
    let state = infer_java_state(source);
    let mut findings = Vec::new();
    let mut sinks = Vec::new();

    for args in method_call_args(source, ".prepareCall") {
        if let Some(argument) = args.first() {
            sinks.push("prepareCall".to_owned());
            findings.push(classify_sink_argument(
                "sql_injection",
                "prepareCall",
                argument,
                &state,
            ));
        }
    }
    for args in method_call_args(source, ".prepareStatement") {
        if let Some(argument) = args.first() {
            sinks.push("prepareStatement".to_owned());
            findings.push(classify_sink_argument(
                "sql_injection",
                "prepareStatement",
                argument,
                &state,
            ));
        }
    }
    for args in method_call_args(source, ".executeQuery") {
        if let Some(argument) = args.first().filter(|argument| !argument.trim().is_empty()) {
            sinks.push("executeQuery".to_owned());
            findings.push(classify_sink_argument(
                "sql_injection",
                "executeQuery",
                argument,
                &state,
            ));
        }
    }
    for args in method_call_args(source, ".search") {
        if args.len() >= 2 {
            sinks.push("ldap_search".to_owned());
            findings.push(classify_sink_argument(
                "ldap_injection",
                "DirContext.search filter",
                &args[1],
                &state,
            ));
        }
    }
    if has_xpath_api(source) {
        for args in method_call_args(source, ".compile") {
            if let Some(argument) = args.first() {
                sinks.push("xpath_compile".to_owned());
                findings.push(classify_sink_argument(
                    "xpath_injection",
                    "XPath.compile expression",
                    argument,
                    &state,
                ));
            }
        }
        for args in method_call_args(source, ".evaluate") {
            if args.len() >= 2 {
                sinks.push("xpath_evaluate".to_owned());
                findings.push(classify_sink_argument(
                    "xpath_injection",
                    "XPath.evaluate expression",
                    &args[0],
                    &state,
                ));
            }
        }
    }
    for args in method_call_args(source, ".putValue") {
        if args.len() >= 2 {
            sinks.push("session_put_value".to_owned());
            findings.push(classify_two_argument_sink(
                "trust_boundary",
                "HttpSession.putValue",
                &args[0],
                &args[1],
                &state,
            ));
        }
    }
    for args in method_call_args(source, ".setAttribute") {
        if args.len() >= 2 {
            sinks.push("session_set_attribute".to_owned());
            findings.push(classify_two_argument_sink(
                "trust_boundary",
                "HttpSession.setAttribute",
                &args[0],
                &args[1],
                &state,
            ));
        }
    }

    let tainted_variables = state
        .strings
        .iter()
        .filter_map(|(name, value)| {
            if matches!(value, ValueState::Tainted(_)) {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    sinks.sort();
    sinks.dedup();

    InjectionAnalysis {
        findings,
        tainted_variables,
        sinks,
    }
}

fn classify_sink_argument(
    category: &str,
    sink: &str,
    argument: &str,
    state: &JavaState,
) -> InjectionSemanticFinding {
    let argument_state = eval_string_expr(argument, state);
    match argument_state {
        ValueState::Tainted(source) => InjectionSemanticFinding {
            category: format!("{category}_tainted_sink"),
            sink: sink.to_owned(),
            risk_level: DANGER.to_owned(),
            evidence: format!(
                "{sink} receives tainted expression `{}` derived from {source}.",
                argument.trim()
            ),
            recommendation: recommendation_for(category),
        },
        ValueState::Constant(_) => InjectionSemanticFinding {
            category: format!("{category}_constant_sink"),
            sink: sink.to_owned(),
            risk_level: NORMAL.to_owned(),
            evidence: format!(
                "{sink} receives expression `{}` that resolves to a constant or benchmark safe helper value.",
                argument.trim()
            ),
            recommendation: "Keep untrusted request data out of this sink or bind it through safe parameter APIs.".to_owned(),
        },
        ValueState::Unknown => InjectionSemanticFinding {
            category: format!("{category}_unknown_sink"),
            sink: sink.to_owned(),
            risk_level: WARNING.to_owned(),
            evidence: format!(
                "{sink} receives expression `{}` but the scanner could not resolve its source.",
                argument.trim()
            ),
            recommendation: "Review the source-to-sink path manually or add a more precise static rule for this pattern.".to_owned(),
        },
    }
}

fn classify_two_argument_sink(
    category: &str,
    sink: &str,
    first_argument: &str,
    second_argument: &str,
    state: &JavaState,
) -> InjectionSemanticFinding {
    let first_state = eval_string_expr(first_argument, state);
    let second_state = eval_string_expr(second_argument, state);
    if let ValueState::Tainted(source) = first_state {
        return InjectionSemanticFinding {
            category: format!("{category}_tainted_sink"),
            sink: sink.to_owned(),
            risk_level: DANGER.to_owned(),
            evidence: format!(
                "{sink} receives tainted key/name expression `{}` derived from {source}.",
                first_argument.trim()
            ),
            recommendation: recommendation_for(category),
        };
    }
    if let ValueState::Tainted(source) = second_state {
        return InjectionSemanticFinding {
            category: format!("{category}_tainted_sink"),
            sink: sink.to_owned(),
            risk_level: DANGER.to_owned(),
            evidence: format!(
                "{sink} receives tainted value expression `{}` derived from {source}.",
                second_argument.trim()
            ),
            recommendation: recommendation_for(category),
        };
    }
    if matches!(first_state, ValueState::Constant(_))
        && matches!(second_state, ValueState::Constant(_))
    {
        return InjectionSemanticFinding {
            category: format!("{category}_constant_sink"),
            sink: sink.to_owned(),
            risk_level: NORMAL.to_owned(),
            evidence: format!(
                "{sink} receives constant key/name `{}` and constant value `{}`.",
                first_argument.trim(),
                second_argument.trim()
            ),
            recommendation:
                "Keep request-controlled data out of session attribute names and sensitive values."
                    .to_owned(),
        };
    }

    InjectionSemanticFinding {
        category: format!("{category}_unknown_sink"),
        sink: sink.to_owned(),
        risk_level: WARNING.to_owned(),
        evidence: format!(
            "{sink} receives key/name `{}` and value `{}`, but the scanner could not resolve both sources.",
            first_argument.trim(),
            second_argument.trim()
        ),
        recommendation: "Review whether untrusted request data controls the session key or value."
            .to_owned(),
    }
}

fn recommendation_for(category: &str) -> String {
    match category {
        "sql_injection" => {
            "Use parameterized PreparedStatement/CallableStatement bindings instead of concatenating request-controlled data into SQL.".to_owned()
        }
        "ldap_injection" => {
            "Avoid concatenating request-controlled data into LDAP filters; escape filter values or use safe parameterized filter APIs.".to_owned()
        }
        "xpath_injection" => {
            "Avoid concatenating request-controlled data into XPath expressions; use safe lookup patterns or strict allow-list validation.".to_owned()
        }
        "trust_boundary" => {
            "Do not let request-controlled data choose session attribute names or security-sensitive session values.".to_owned()
        }
        _ => "Avoid concatenating request-controlled data into interpreter strings.".to_owned(),
    }
}

fn infer_java_state(source: &str) -> JavaState {
    let mut state = JavaState::default();
    let mut pending = String::new();
    for raw_line in source.lines() {
        let Some(line) = cleaned_statement_line(raw_line) else {
            continue;
        };
        if pending.is_empty() {
            pending.push_str(&line);
        } else {
            pending.push(' ');
            pending.push_str(line.trim());
        }
        if !statement_is_complete(&pending) {
            continue;
        }

        let statement = pending.trim().to_owned();
        pending.clear();
        if let Some((name, value)) = parse_int_assignment(&statement, &state.ints) {
            state.ints.insert(name, value);
            continue;
        }
        if let Some((name, value)) = parse_string_assignment(&statement, &state) {
            state.strings.insert(name, value);
        }
    }
    if !pending.trim().is_empty() {
        if let Some((name, value)) = parse_string_assignment(pending.trim(), &state) {
            state.strings.insert(name, value);
        }
    }
    state
}

fn statement_is_complete(statement: &str) -> bool {
    let trimmed = statement.trim();
    trimmed.ends_with(';') || trimmed.ends_with('{') || trimmed.ends_with('}')
}

fn cleaned_statement_line(raw_line: &str) -> Option<String> {
    let line = strip_line_comment(raw_line).trim().to_owned();
    if line.is_empty()
        || line.starts_with('*')
        || line.starts_with("/*")
        || line.starts_with('@')
        || line.starts_with("if ")
        || line.starts_with("if(")
        || line.starts_with("else")
        || line.starts_with("for ")
        || line.starts_with("while ")
        || line.starts_with("try")
        || line.starts_with("catch")
        || line.starts_with("return")
    {
        return None;
    }
    Some(line)
}

fn strip_line_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if !in_string && line[idx..].starts_with("//") {
            return &line[..idx];
        }
    }
    line
}

fn parse_int_assignment(line: &str, ints: &HashMap<String, i64>) -> Option<(String, i64)> {
    let declaration = line.strip_prefix("int ")?;
    let (name, expr) = declaration.split_once('=')?;
    let name = name.trim();
    if !is_java_identifier(name) {
        return None;
    }
    let value = eval_int_expr(expr.trim_end_matches(';').trim(), ints)?;
    Some((name.to_owned(), value))
}

fn parse_string_assignment(line: &str, state: &JavaState) -> Option<(String, ValueState)> {
    if let Some(declaration) = line.strip_prefix("String ") {
        if let Some((name, expr)) = declaration.split_once('=') {
            let name = name.trim();
            if is_java_identifier(name) {
                return Some((name.to_owned(), eval_string_expr(expr, state)));
            }
        } else {
            let name = declaration.trim_end_matches(';').trim();
            if is_java_identifier(name) {
                return Some((name.to_owned(), ValueState::Unknown));
            }
        }
    }

    let (name, expr) = split_assignment(line)?;
    if is_java_identifier(name) {
        Some((name.to_owned(), eval_string_expr(expr, state)))
    } else {
        None
    }
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    for (idx, ch) in line.char_indices() {
        if ch != '=' {
            continue;
        }
        let previous = line[..idx].chars().next_back();
        let next = line[idx + 1..].chars().next();
        if matches!(previous, Some('=' | '!' | '<' | '>')) || next == Some('=') {
            continue;
        }
        return Some((line[..idx].trim(), line[idx + 1..].trim()));
    }
    None
}

fn eval_string_expr(expr: &str, state: &JavaState) -> ValueState {
    let expr = expr.trim().trim_end_matches(';').trim();
    if let Some((condition, true_expr, false_expr)) = split_ternary(expr) {
        return match eval_bool_expr(condition, &state.ints) {
            Some(true) => eval_string_expr(true_expr, state),
            Some(false) => eval_string_expr(false_expr, state),
            None => {
                let true_state = eval_string_expr(true_expr, state);
                let false_state = eval_string_expr(false_expr, state);
                combine_branch_states(true_state, false_state)
            }
        };
    }
    if expr.contains("request.getHeader(") {
        return ValueState::Tainted(http_source("request.getHeader", expr));
    }
    if expr.contains("request.getParameter(") {
        return ValueState::Tainted(http_source("request.getParameter", expr));
    }
    if expr.contains(".getTheParameter(") || expr.contains(".getTheCookie(") {
        return ValueState::Tainted(http_source("benchmark helper request source", expr));
    }
    if expr.contains(".getTheValue(") {
        return ValueState::Constant("benchmark safe helper value".to_owned());
    }
    if expr.contains("URLDecoder.decode(") || expr.contains(".trim(") || expr.contains(".toString(") {
        if let Some(inner) = first_argument_after_open_paren(expr) {
            return eval_string_expr(&inner, state);
        }
    }
    if let Some(name) = expr.strip_prefix('(').and_then(|value| value.strip_suffix(')')) {
        return eval_string_expr(name, state);
    }
    if is_quoted_string(expr) {
        return ValueState::Constant(unquote(expr));
    }
    if is_java_identifier(expr) {
        return state.strings.get(expr).cloned().unwrap_or(ValueState::Unknown);
    }
    if let Some((name, value)) = expr_tainted_variable(expr, &state.strings) {
        return ValueState::Tainted(format!("tainted variable `{name}` ({value})"));
    }
    if expr.contains('+') && expression_references_only_known_constants(expr, &state.strings) {
        return ValueState::Constant("constant expression".to_owned());
    }
    ValueState::Unknown
}

fn split_ternary(expr: &str) -> Option<(&str, &str, &str)> {
    let question = expr.find('?')?;
    let colon = expr[question + 1..].find(':')? + question + 1;
    Some((
        expr[..question].trim(),
        expr[question + 1..colon].trim(),
        expr[colon + 1..].trim(),
    ))
}

fn combine_branch_states(left: ValueState, right: ValueState) -> ValueState {
    match (left, right) {
        (ValueState::Tainted(source), _) | (_, ValueState::Tainted(source)) => {
            ValueState::Tainted(format!("possible branch source {source}"))
        }
        (ValueState::Constant(left), ValueState::Constant(right)) if left == right => {
            ValueState::Constant(left)
        }
        (ValueState::Constant(_), ValueState::Constant(_)) => ValueState::Unknown,
        _ => ValueState::Unknown,
    }
}

fn http_source(kind: &str, expr: &str) -> String {
    let name = first_string_argument(expr).unwrap_or_else(|| "unknown".to_owned());
    format!("{kind}(\"{name}\")")
}

fn first_argument_after_open_paren(expr: &str) -> Option<String> {
    let open = expr.find('(')?;
    let args = split_arguments(&expr[open + 1..expr.rfind(')')?]);
    args.into_iter().next()
}

fn expr_tainted_variable(
    expr: &str,
    strings: &HashMap<String, ValueState>,
) -> Option<(String, String)> {
    for (name, value) in strings {
        if let ValueState::Tainted(source) = value {
            if contains_identifier(expr, name) {
                return Some((name.clone(), source.clone()));
            }
        }
    }
    None
}

fn expression_references_only_known_constants(
    expr: &str,
    strings: &HashMap<String, ValueState>,
) -> bool {
    let identifiers = identifiers_in_expr(expr);
    identifiers.into_iter().all(|identifier| {
        matches!(
            strings.get(&identifier),
            Some(ValueState::Constant(_)) | None
        )
    })
}

fn identifiers_in_expr(expr: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in expr.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            if current.chars().next().is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic()) {
                identifiers.push(current.clone());
            }
            current.clear();
        }
    }
    if !current.is_empty()
        && current
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        identifiers.push(current);
    }
    identifiers
}

fn method_call_args(source: &str, needle: &str) -> Vec<Vec<String>> {
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(needle) {
        let method_end = offset + relative + needle.len();
        let Some(open_relative) = source[method_end..].find('(') else {
            break;
        };
        let open = method_end + open_relative;
        if let Some(close) = matching_close_paren(source, open) {
            calls.push(split_arguments(&source[open + 1..close]));
            offset = close + 1;
        } else {
            offset = method_end;
        }
    }
    calls
}

fn has_xpath_api(source: &str) -> bool {
    source.contains("javax.xml.xpath")
        || source.contains("XPathFactory")
        || source.contains("XPathConstants")
}

fn matching_close_paren(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (relative, ch) in source[open..].char_indices() {
        let idx = open + relative;
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_arguments(arguments: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in arguments.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                values.push(arguments[start..idx].trim().to_owned());
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = arguments[start..].trim();
    if !tail.is_empty() {
        values.push(tail.to_owned());
    }
    values
}

fn first_string_argument(expr: &str) -> Option<String> {
    let start = expr.find('"')? + 1;
    let mut output = String::new();
    let mut escaped = false;
    for ch in expr[start..].chars() {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(output);
        } else {
            output.push(ch);
        }
    }
    None
}

fn is_quoted_string(expr: &str) -> bool {
    let trimmed = expr.trim();
    if !trimmed.starts_with('"') {
        return false;
    }
    let mut escaped = false;
    for (idx, ch) in trimmed[1..].char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return trimmed[idx + 2..].trim().is_empty();
        }
    }
    false
}

fn unquote(expr: &str) -> String {
    let trimmed = expr.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_owned()
}

fn contains_identifier(expr: &str, name: &str) -> bool {
    identifiers_in_expr(expr)
        .iter()
        .any(|identifier| identifier == name)
}

fn is_java_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn eval_bool_expr(expr: &str, ints: &HashMap<String, i64>) -> Option<bool> {
    for operator in [">=", "<=", "==", "!=", ">", "<"] {
        if let Some((left, right)) = expr.split_once(operator) {
            let left = eval_int_expr(left.trim(), ints)?;
            let right = eval_int_expr(right.trim(), ints)?;
            return Some(match operator {
                ">=" => left >= right,
                "<=" => left <= right,
                "==" => left == right,
                "!=" => left != right,
                ">" => left > right,
                "<" => left < right,
                _ => return None,
            });
        }
    }
    None
}

fn eval_int_expr(expr: &str, ints: &HashMap<String, i64>) -> Option<i64> {
    let tokens = tokenize_int_expr(expr);
    if tokens.is_empty() {
        return None;
    }
    let mut parser = IntParser {
        tokens,
        offset: 0,
        ints,
    };
    let value = parser.parse_expr()?;
    if parser.offset == parser.tokens.len() {
        Some(value)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IntToken {
    Number(i64),
    Ident(String),
    Plus,
    Minus,
    Star,
    LParen,
    RParen,
}

fn tokenize_int_expr(expr: &str) -> Vec<IntToken> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
        } else if ch.is_ascii_digit() {
            let mut number = String::new();
            while let Some(ch) = chars.peek().copied().filter(char::is_ascii_digit) {
                number.push(ch);
                chars.next();
            }
            if let Ok(value) = number.parse::<i64>() {
                tokens.push(IntToken::Number(value));
            }
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let mut ident = String::new();
            while let Some(next) = chars
                .peek()
                .copied()
                .filter(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                ident.push(next);
                chars.next();
            }
            tokens.push(IntToken::Ident(ident));
        } else {
            chars.next();
            match ch {
                '+' => tokens.push(IntToken::Plus),
                '-' => tokens.push(IntToken::Minus),
                '*' => tokens.push(IntToken::Star),
                '(' => tokens.push(IntToken::LParen),
                ')' => tokens.push(IntToken::RParen),
                _ => {}
            }
        }
    }
    tokens
}

struct IntParser<'a> {
    tokens: Vec<IntToken>,
    offset: usize,
    ints: &'a HashMap<String, i64>,
}

impl IntParser<'_> {
    fn parse_expr(&mut self) -> Option<i64> {
        let mut value = self.parse_term()?;
        while let Some(token) = self.tokens.get(self.offset) {
            match token {
                IntToken::Plus => {
                    self.offset += 1;
                    value += self.parse_term()?;
                }
                IntToken::Minus => {
                    self.offset += 1;
                    value -= self.parse_term()?;
                }
                _ => break,
            }
        }
        Some(value)
    }

    fn parse_term(&mut self) -> Option<i64> {
        let mut value = self.parse_factor()?;
        while matches!(self.tokens.get(self.offset), Some(IntToken::Star)) {
            self.offset += 1;
            value *= self.parse_factor()?;
        }
        Some(value)
    }

    fn parse_factor(&mut self) -> Option<i64> {
        let token = self.tokens.get(self.offset)?.clone();
        self.offset += 1;
        match token {
            IntToken::Number(value) => Some(value),
            IntToken::Ident(name) => self.ints.get(&name).copied(),
            IntToken::Minus => Some(-self.parse_factor()?),
            IntToken::Plus => self.parse_factor(),
            IntToken::LParen => {
                let value = self.parse_expr()?;
                if matches!(self.tokens.get(self.offset), Some(IntToken::RParen)) {
                    self.offset += 1;
                    Some(value)
                } else {
                    None
                }
            }
            IntToken::RParen | IntToken::Star => None,
        }
    }
}

fn default_source_root() -> String {
    DEFAULT_BENCHMARK_SOURCE_ROOT.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolRegistry;

    #[test]
    fn classifies_header_sql_prepare_call_as_danger() {
        let source = r#"
            String param = request.getHeader("vector");
            if (param == null) param = "";
            param = java.net.URLDecoder.decode(param, "UTF-8");
            String sql = "{call " + param + "}";
            connection.prepareCall(sql);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, DANGER);
        assert_eq!(analysis.findings[0].category, "sql_injection_tainted_sink");
        assert_eq!(analysis.tainted_variables, vec!["param", "sql"]);
    }

    #[test]
    fn classifies_safe_helper_sql_prepare_call_as_normal() {
        let source = r#"
            org.owasp.benchmark.helpers.SeparateClassRequest scr =
                new org.owasp.benchmark.helpers.SeparateClassRequest(request);
            String param = scr.getTheValue("vector");
            String sql = "{call " + param + "}";
            connection.prepareCall(sql);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, NORMAL);
        assert_eq!(analysis.findings[0].category, "sql_injection_constant_sink");
    }

    #[test]
    fn classifies_constant_ternary_ldap_filter_as_normal() {
        let source = r#"
            String param = request.getHeader("vector");
            int num = 106;
            String bar;
            bar = (7*18) + num > 200 ? "This_should_always_happen" : param;
            String filter = "(&(objectclass=person))(|(uid="+bar+")(street={0}))";
            idc.search(base, filter, filters, sc);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, NORMAL);
        assert_eq!(analysis.findings[0].category, "ldap_injection_constant_sink");
    }

    #[test]
    fn classifies_tainted_ldap_filter_as_danger() {
        let source = r#"
            String param = request.getParameter("uid");
            String filter = "(uid=" + param + ")";
            idc.search(base, filter, filters, sc);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, DANGER);
        assert_eq!(analysis.findings[0].category, "ldap_injection_tainted_sink");
    }

    #[test]
    fn classifies_tainted_xpath_evaluate_as_danger() {
        let source = r#"
            javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String param = request.getHeader("vector");
            String expression = "/Employees/Employee[@emplid='" + param + "']";
            xp.evaluate(expression, xmlDocument);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, DANGER);
        assert_eq!(analysis.findings[0].category, "xpath_injection_tainted_sink");
    }

    #[test]
    fn preserves_taint_through_base64_style_wrapper_for_xpath() {
        let source = r#"
            javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String param = request.getHeader("vector");
            String bar = new String(new sun.misc.BASE64Decoder().decodeBuffer(
                new sun.misc.BASE64Encoder().encode(param.getBytes())));
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression, xmlDocument);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, DANGER);
        assert_eq!(analysis.findings[0].category, "xpath_injection_tainted_sink");
    }

    #[test]
    fn classifies_constant_xpath_compile_as_normal() {
        let source = r#"
            javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String bar = "safe!";
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, NORMAL);
        assert_eq!(analysis.findings[0].category, "xpath_injection_constant_sink");
    }

    #[test]
    fn classifies_tainted_session_attribute_as_danger() {
        let source = r#"
            String param = request.getParameter("vector");
            request.getSession().setAttribute(param, "10340");
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, DANGER);
        assert_eq!(analysis.findings[0].category, "trust_boundary_tainted_sink");
    }

    #[test]
    fn classifies_constant_session_attribute_as_normal() {
        let source = r#"
            String param = request.getHeader("vector");
            int num = 106;
            String bar;
            bar = (7*18) + num > 200 ? "This_should_always_happen" : param;
            request.getSession().putValue(bar, "10340");
        "#;

        let analysis = analyze_java_injection_source(source);

        assert_eq!(analysis.findings[0].risk_level, NORMAL);
        assert_eq!(analysis.findings[0].category, "trust_boundary_constant_sink");
    }

    #[test]
    fn evaluates_simple_integer_conditions() {
        let mut ints = HashMap::new();
        ints.insert("num".to_owned(), 106);

        assert_eq!(eval_bool_expr("(7*18) + num > 200", &ints), Some(true));
    }

    #[test]
    fn blank_source_path_falls_back_to_case_id() {
        let input = JavaInjectionSemanticInput {
            case_id: Some("BenchmarkTest00008".to_owned()),
            source_path: Some(" ".to_owned()),
            source_root: "target/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"
                .to_owned(),
        };

        let path = resolve_source_path(&input, "java_injection_semantic_scan")
            .expect("path should resolve");

        assert!(path.ends_with("BenchmarkTest00008.java"));
    }

    #[test]
    fn registry_includes_java_injection_semantic_scan_tool() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("java_injection_semantic_scan"));
    }
}
