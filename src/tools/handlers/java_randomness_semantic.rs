use std::collections::BTreeSet;
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
pub struct JavaRandomnessSemanticScanTool;

#[async_trait]
impl ToolHandler for JavaRandomnessSemanticScanTool {
    fn name(&self) -> &'static str {
        "java_randomness_semantic_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Statically inspect a Java source file or OWASP Benchmark case for weak randomness APIs, distinguishing java.util.Random/Math.random from SecureRandom usage.",
            json!({
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "Optional OWASP Benchmark case ID such as BenchmarkTest00023. Used with source_root when source_path is omitted."
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
        let input: JavaRandomnessSemanticInput =
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
struct JavaRandomnessSemanticInput {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default = "default_source_root")]
    source_root: String,
}

#[derive(Debug, Serialize)]
struct JavaRandomnessSemanticReport {
    source_path: String,
    case_id: Option<String>,
    risk_level: String,
    summary: String,
    findings: Vec<RandomnessSemanticFinding>,
    apis: Vec<String>,
}

impl JavaRandomnessSemanticReport {
    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct RandomnessSemanticFinding {
    category: String,
    api: String,
    risk_level: String,
    evidence: String,
    recommendation: String,
}

fn run_scan(
    input: JavaRandomnessSemanticInput,
    tool: &str,
) -> Result<JavaRandomnessSemanticReport> {
    let source_path = resolve_source_path(&input, tool)?;
    let source = fs::read_to_string(&source_path).map_err(|error| ToolError::Execution {
        tool: tool.to_owned(),
        message: format!("failed to read {}: {error}", source_path.display()),
    })?;
    let findings = analyze_java_randomness_source(&source);
    let risk_level =
        risk::max_label(findings.iter().map(|finding| finding.risk_level.as_str())).to_owned();
    let apis = findings
        .iter()
        .map(|finding| finding.api.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let summary = if findings.is_empty() {
        "Java randomness semantic scan completed: no recognized Java randomness API calls found."
            .to_owned()
    } else {
        let weak = findings
            .iter()
            .filter(|finding| finding.risk_level == DANGER)
            .count();
        let strong = findings
            .iter()
            .filter(|finding| finding.risk_level == NORMAL)
            .count();
        let warning = findings
            .iter()
            .filter(|finding| finding.risk_level == WARNING)
            .count();
        format!(
            "Java randomness semantic scan completed: {} finding(s), {weak} weak, {strong} strong, {warning} uncertain, overall risk {risk_level}.",
            findings.len()
        )
    };

    Ok(JavaRandomnessSemanticReport {
        source_path: source_path.display().to_string(),
        case_id: input.case_id,
        risk_level,
        summary,
        findings,
        apis,
    })
}

fn resolve_source_path(input: &JavaRandomnessSemanticInput, tool: &str) -> Result<PathBuf> {
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

fn analyze_java_randomness_source(source: &str) -> Vec<RandomnessSemanticFinding> {
    let mut findings = Vec::new();
    let stripped = strip_java_comments(source);

    if contains_math_random(&stripped) {
        findings.push(weak_random_finding(
            "java.lang.Math.random",
            "Math.random uses a general-purpose PRNG and is not appropriate for security-sensitive tokens.",
        ));
    }
    if contains_java_util_random(&stripped) {
        findings.push(weak_random_finding(
            "java.util.Random",
            "java.util.Random is predictable and not appropriate for security-sensitive tokens.",
        ));
    }
    if contains_thread_local_random(&stripped) {
        findings.push(weak_random_finding(
            "java.util.concurrent.ThreadLocalRandom",
            "ThreadLocalRandom is optimized for concurrency, not cryptographic unpredictability.",
        ));
    }
    if contains_secure_random(&stripped) {
        findings.push(RandomnessSemanticFinding {
            category: "cryptographic_randomness".to_owned(),
            api: "java.security.SecureRandom".to_owned(),
            risk_level: NORMAL.to_owned(),
            evidence: "Source uses java.security.SecureRandom for random value generation."
                .to_owned(),
            recommendation:
                "Keep using SecureRandom for security-sensitive randomness and avoid predictable seeds."
                    .to_owned(),
        });
    }

    if findings.is_empty() && has_randomness_banner(&stripped) {
        findings.push(RandomnessSemanticFinding {
            category: "runtime_banner_without_api".to_owned(),
            api: "unknown".to_owned(),
            risk_level: WARNING.to_owned(),
            evidence:
                "Source mentions a weak-randomness benchmark banner, but no recognized randomness API was found."
                    .to_owned(),
            recommendation: "Inspect the generated value source manually or add a rule for the wrapper API."
                .to_owned(),
        });
    }

    findings
}

fn weak_random_finding(api: &str, evidence: &str) -> RandomnessSemanticFinding {
    RandomnessSemanticFinding {
        category: "weak_randomness_api".to_owned(),
        api: api.to_owned(),
        risk_level: DANGER.to_owned(),
        evidence: evidence.to_owned(),
        recommendation:
            "Use java.security.SecureRandom or another CSPRNG-backed generator with enough entropy."
                .to_owned(),
    }
}

fn contains_math_random(source: &str) -> bool {
    source.contains("Math.random(") || source.contains("java.lang.Math.random(")
}

fn contains_java_util_random(source: &str) -> bool {
    source.contains("new java.util.Random(") || source.contains("new Random(")
}

fn contains_thread_local_random(source: &str) -> bool {
    source.contains("ThreadLocalRandom.current(")
        || source.contains("java.util.concurrent.ThreadLocalRandom.current(")
}

fn contains_secure_random(source: &str) -> bool {
    source.contains("new java.security.SecureRandom(")
        || source.contains("new SecureRandom(")
        || source.contains("java.security.SecureRandom.getInstance(")
        || source.contains("SecureRandom.getInstance(")
}

fn has_randomness_banner(source: &str) -> bool {
    source.contains("Weak Randomness Test")
}

fn strip_java_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                output.push(ch);
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                output.push(ch);
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
        } else {
            output.push(ch);
        }
    }

    output
}

fn default_source_root() -> String {
    DEFAULT_BENCHMARK_SOURCE_ROOT.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolRegistry;

    #[test]
    fn classifies_math_random_as_weak() {
        let findings = analyze_java_randomness_source(r#"double value = java.lang.Math.random();"#);

        assert_eq!(findings[0].risk_level, DANGER);
        assert_eq!(findings[0].category, "weak_randomness_api");
    }

    #[test]
    fn classifies_java_util_random_as_weak() {
        let findings =
            analyze_java_randomness_source(r#"float rand = new java.util.Random().nextFloat();"#);

        assert_eq!(findings[0].risk_level, DANGER);
        assert_eq!(findings[0].api, "java.util.Random");
    }

    #[test]
    fn classifies_secure_random_as_normal() {
        let findings = analyze_java_randomness_source(
            r#"int randNumber = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);"#,
        );

        assert_eq!(findings[0].risk_level, NORMAL);
        assert_eq!(findings[0].api, "java.security.SecureRandom");
    }

    #[test]
    fn declared_random_type_backed_by_secure_random_is_not_weak() {
        let findings = analyze_java_randomness_source(
            r#"java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");"#,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk_level, NORMAL);
        assert_eq!(findings[0].api, "java.security.SecureRandom");
    }

    #[test]
    fn comments_do_not_create_findings() {
        let findings = analyze_java_randomness_source(
            r#"
            // new java.util.Random().nextInt();
            java.security.SecureRandom.getInstance("SHA1PRNG").nextInt();
            "#,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk_level, NORMAL);
    }

    #[test]
    fn runtime_banner_string_does_not_create_finding() {
        let findings = analyze_java_randomness_source(
            r#"response.getWriter().println("Weak Randomness Test java.util.Random.nextInt() executed");"#,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn blank_source_path_falls_back_to_case_id() {
        let input = JavaRandomnessSemanticInput {
            case_id: Some("BenchmarkTest00023".to_owned()),
            source_path: Some(" ".to_owned()),
            source_root: "target/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"
                .to_owned(),
        };

        let path = resolve_source_path(&input, "java_randomness_semantic_scan")
            .expect("path should resolve");

        assert!(path.ends_with("BenchmarkTest00023.java"));
    }

    #[test]
    fn registry_includes_java_randomness_semantic_scan_tool() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("java_randomness_semantic_scan"));
    }
}
