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
pub struct JavaCryptoSemanticScanTool;

#[async_trait]
impl ToolHandler for JavaCryptoSemanticScanTool {
    fn name(&self) -> &'static str {
        "java_crypto_semantic_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Statically inspect a Java source file or OWASP Benchmark case for hash and crypto algorithms, distinguishing weak algorithms from safe MessageDigest/Cipher usage.",
            json!({
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "Optional OWASP Benchmark case ID such as BenchmarkTest00009. Used with source_root when source_path is omitted."
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
        let input: JavaCryptoSemanticInput =
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
struct JavaCryptoSemanticInput {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default = "default_source_root")]
    source_root: String,
}

#[derive(Debug, Serialize)]
struct JavaCryptoSemanticReport {
    source_path: String,
    case_id: Option<String>,
    risk_level: String,
    summary: String,
    findings: Vec<CryptoSemanticFinding>,
    algorithms: Vec<String>,
}

impl JavaCryptoSemanticReport {
    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct CryptoSemanticFinding {
    category: String,
    algorithm: String,
    risk_level: String,
    evidence: String,
    recommendation: String,
}

fn run_scan(input: JavaCryptoSemanticInput, tool: &str) -> Result<JavaCryptoSemanticReport> {
    let source_path = resolve_source_path(&input, tool)?;
    let source = fs::read_to_string(&source_path).map_err(|error| ToolError::Execution {
        tool: tool.to_owned(),
        message: format!("failed to read {}: {error}", source_path.display()),
    })?;
    let findings = analyze_java_crypto_source(&source);
    let risk_level =
        risk::max_label(findings.iter().map(|finding| finding.risk_level.as_str())).to_owned();
    let algorithms = findings
        .iter()
        .map(|finding| finding.algorithm.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let summary = if findings.is_empty() {
        "Java crypto semantic scan completed: no MessageDigest/Cipher getInstance calls found."
            .to_owned()
    } else {
        let dangerous = findings
            .iter()
            .filter(|finding| finding.risk_level == DANGER)
            .count();
        let normal = findings
            .iter()
            .filter(|finding| finding.risk_level == NORMAL)
            .count();
        format!(
            "Java crypto semantic scan completed: {} finding(s), {dangerous} weak, {normal} acceptable, overall risk {risk_level}.",
            findings.len()
        )
    };

    Ok(JavaCryptoSemanticReport {
        source_path: source_path.display().to_string(),
        case_id: input.case_id,
        risk_level,
        summary,
        findings,
        algorithms,
    })
}

fn resolve_source_path(input: &JavaCryptoSemanticInput, tool: &str) -> Result<PathBuf> {
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

fn analyze_java_crypto_source(source: &str) -> Vec<CryptoSemanticFinding> {
    let mut findings = Vec::new();
    for algorithm in get_instance_algorithms(source, "MessageDigest.getInstance") {
        findings.push(classify_hash_algorithm(&algorithm));
    }
    for transformation in get_instance_algorithms(source, "Cipher.getInstance") {
        findings.push(classify_cipher_transformation(&transformation));
    }
    findings
}

fn get_instance_algorithms(source: &str, target: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(target) {
        let target_start = offset + relative;
        let after_target = target_start + target.len();
        if let Some(value) = first_string_argument(&source[after_target..]) {
            push_unique(&mut values, value);
        }
        offset = after_target;
    }
    values
}

fn first_string_argument(after_target: &str) -> Option<String> {
    let open = after_target.find('(')?;
    let mut chars = after_target[open + 1..].char_indices().peekable();
    while let Some((_, ch)) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
    if chars.next()?.1 != '"' {
        return None;
    }

    let mut output = String::new();
    let mut escaped = false;
    for (_, ch) in chars {
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

fn classify_hash_algorithm(algorithm: &str) -> CryptoSemanticFinding {
    let normalized = normalize_algorithm(algorithm);
    if matches!(normalized.as_str(), "MD2" | "MD4" | "MD5" | "SHA1") {
        return CryptoSemanticFinding {
            category: "weak_hash_algorithm".to_owned(),
            algorithm: algorithm.to_owned(),
            risk_level: DANGER.to_owned(),
            evidence: format!("MessageDigest.getInstance uses weak hash algorithm `{algorithm}`."),
            recommendation: "Use SHA-256/SHA-384/SHA-512 or a purpose-built password hashing scheme such as Argon2, bcrypt, scrypt, or PBKDF2 for passwords.".to_owned(),
        };
    }

    if normalized.starts_with("SHA2")
        || normalized.starts_with("SHA3")
        || matches!(
            normalized.as_str(),
            "SHA224" | "SHA256" | "SHA384" | "SHA512"
        )
    {
        return CryptoSemanticFinding {
            category: "acceptable_hash_algorithm".to_owned(),
            algorithm: algorithm.to_owned(),
            risk_level: NORMAL.to_owned(),
            evidence: format!("MessageDigest.getInstance uses acceptable hash algorithm `{algorithm}`."),
            recommendation: "Keep using collision-resistant hashes for integrity use cases; use a password hashing scheme for stored passwords.".to_owned(),
        };
    }

    CryptoSemanticFinding {
        category: "unknown_hash_algorithm".to_owned(),
        algorithm: algorithm.to_owned(),
        risk_level: WARNING.to_owned(),
        evidence: format!("MessageDigest.getInstance uses unclassified hash algorithm `{algorithm}`."),
        recommendation: "Manually verify whether the algorithm is collision-resistant and appropriate for the stored data.".to_owned(),
    }
}

fn classify_cipher_transformation(transformation: &str) -> CryptoSemanticFinding {
    let parts = transformation
        .split('/')
        .map(|part| part.trim().to_ascii_uppercase())
        .collect::<Vec<_>>();
    let algorithm = parts.first().map(String::as_str).unwrap_or_default();
    let mode = parts.get(1).map(String::as_str);

    if matches!(
        algorithm,
        "DES" | "DESEDE" | "TRIPLEDES" | "RC2" | "RC4" | "ARCFOUR"
    ) {
        return weak_cipher_finding(
            transformation,
            format!("Cipher.getInstance uses weak cipher algorithm `{algorithm}`."),
        );
    }
    if mode == Some("ECB") {
        return weak_cipher_finding(
            transformation,
            "Cipher.getInstance uses ECB mode, which leaks block patterns.".to_owned(),
        );
    }
    if parts.len() == 1 && algorithm == "AES" {
        return weak_cipher_finding(
            transformation,
            "Cipher.getInstance(\"AES\") relies on provider defaults, commonly AES/ECB/PKCS5Padding.".to_owned(),
        );
    }

    if algorithm == "AES"
        && matches!(mode, Some("CBC") | Some("GCM") | Some("CTR"))
        && parts.get(2).is_some()
    {
        return CryptoSemanticFinding {
            category: "acceptable_cipher_transformation".to_owned(),
            algorithm: transformation.to_owned(),
            risk_level: NORMAL.to_owned(),
            evidence: format!(
                "Cipher.getInstance uses acceptable benchmark transformation `{transformation}`."
            ),
            recommendation: "Keep authenticated encryption or carefully managed IV/MAC handling in place for production use.".to_owned(),
        };
    }

    CryptoSemanticFinding {
        category: "unknown_cipher_transformation".to_owned(),
        algorithm: transformation.to_owned(),
        risk_level: WARNING.to_owned(),
        evidence: format!("Cipher.getInstance uses unclassified transformation `{transformation}`."),
        recommendation: "Manually verify cipher, mode, padding, key generation, IV uniqueness, and authentication.".to_owned(),
    }
}

fn weak_cipher_finding(transformation: &str, evidence: String) -> CryptoSemanticFinding {
    CryptoSemanticFinding {
        category: "weak_cipher_transformation".to_owned(),
        algorithm: transformation.to_owned(),
        risk_level: DANGER.to_owned(),
        evidence,
        recommendation: "Use AES-GCM or another authenticated encryption mode with strong keys and unique nonces/IVs.".to_owned(),
    }
}

fn normalize_algorithm(algorithm: &str) -> String {
    algorithm
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
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
    fn classifies_sha384_as_acceptable_hash() {
        let finding = classify_hash_algorithm("sha-384");

        assert_eq!(finding.risk_level, NORMAL);
        assert_eq!(finding.category, "acceptable_hash_algorithm");
    }

    #[test]
    fn classifies_md5_as_weak_hash() {
        let finding = classify_hash_algorithm("MD5");

        assert_eq!(finding.risk_level, DANGER);
        assert_eq!(finding.category, "weak_hash_algorithm");
    }

    #[test]
    fn classifies_aes_cbc_pkcs5_as_acceptable_cipher() {
        let finding = classify_cipher_transformation("AES/CBC/PKCS5PADDING");

        assert_eq!(finding.risk_level, NORMAL);
        assert_eq!(finding.category, "acceptable_cipher_transformation");
    }

    #[test]
    fn classifies_aes_ecb_as_weak_cipher() {
        let finding = classify_cipher_transformation("AES/ECB/PKCS5Padding");

        assert_eq!(finding.risk_level, DANGER);
        assert_eq!(finding.category, "weak_cipher_transformation");
    }

    #[test]
    fn extracts_get_instance_first_string_arguments() {
        let source = r#"
            java.security.MessageDigest.getInstance("sha-384", provider[0]);
            javax.crypto.Cipher.getInstance("AES/CBC/PKCS5PADDING", provider);
        "#;

        assert_eq!(
            get_instance_algorithms(source, "MessageDigest.getInstance"),
            vec!["sha-384".to_owned()]
        );
        assert_eq!(
            get_instance_algorithms(source, "Cipher.getInstance"),
            vec!["AES/CBC/PKCS5PADDING".to_owned()]
        );
    }

    #[test]
    fn blank_source_path_falls_back_to_case_id() {
        let input = JavaCryptoSemanticInput {
            case_id: Some("BenchmarkTest00009".to_owned()),
            source_path: Some(" ".to_owned()),
            source_root: "target/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"
                .to_owned(),
        };

        let path =
            resolve_source_path(&input, "java_crypto_semantic_scan").expect("path should resolve");

        assert!(path.ends_with("BenchmarkTest00009.java"));
    }

    #[test]
    fn registry_includes_java_crypto_semantic_scan_tool() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("java_crypto_semantic_scan"));
    }
}
