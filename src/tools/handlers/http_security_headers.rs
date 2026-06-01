use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ORIGIN, SET_COOKIE};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolProgress, ToolProgressCallback,
    ToolSpec,
    risk::{self, DANGER, NORMAL, WARNING},
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 15_000;
const BODY_PREVIEW_LIMIT: usize = 1_000;
const PROBE_ORIGIN: &str = "https://security-probe.invalid";

#[derive(Debug, Clone, Copy)]
pub struct HttpSecurityHeadersScanTool;

#[async_trait]
impl ToolHandler for HttpSecurityHeadersScanTool {
    fn name(&self) -> &'static str {
        "http_security_headers_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Scan an HTTP endpoint for defensive header, CORS, cookie, cache, and server fingerprint configuration risks.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint to scan."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method.",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers.",
                        "additionalProperties": { "type": "string" }
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Additional query parameters to include when scanning.",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "description": "Optional request body. Objects and arrays are sent as JSON; strings are sent as raw text."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 500,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS
                    }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        self.run(call, None).await
    }

    async fn handle_with_progress(
        &self,
        call: ToolCall,
        progress: ToolProgressCallback,
    ) -> Result<ToolOutput> {
        self.run(call, Some(progress)).await
    }
}

impl HttpSecurityHeadersScanTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: SecurityHeadersInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;
        let plan = input.into_plan(self.name())?;
        let report = run_scan(plan, progress).await;
        let metadata = serde_json::to_value(&report).map_err(|error| ToolError::Execution {
            tool: self.name().to_owned(),
            message: error.to_string(),
        })?;

        Ok(ToolOutput::text(call.id, report.summary()).with_metadata(metadata))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SecurityHeadersInput {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    query_params: HashMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Clone)]
struct ScanPlan {
    url: Url,
    method: Method,
    headers: HeaderMap,
    query_params: HashMap<String, String>,
    body: Option<Value>,
    timeout_ms: u64,
}

impl SecurityHeadersInput {
    fn into_plan(self, tool: &str) -> Result<ScanPlan> {
        let url = Url::parse(&self.url).map_err(|error| invalid(tool, error.to_string()))?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => return Err(invalid(tool, format!("unsupported URL scheme: {scheme}"))),
        }

        let method = Method::from_str(&self.method.to_ascii_uppercase())
            .map_err(|error| invalid(tool, error.to_string()))?;
        if !matches!(
            method,
            Method::GET
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
                | Method::HEAD
                | Method::OPTIONS
        ) {
            return Err(invalid(tool, format!("unsupported HTTP method: {method}")));
        }

        let mut headers = HeaderMap::new();
        for (name, value) in self.headers {
            let name =
                HeaderName::from_str(&name).map_err(|error| invalid(tool, error.to_string()))?;
            let value =
                HeaderValue::from_str(&value).map_err(|error| invalid(tool, error.to_string()))?;
            headers.insert(name, value);
        }

        Ok(ScanPlan {
            url,
            method,
            headers,
            query_params: self.query_params,
            body: self.body,
            timeout_ms: bounded(tool, "timeout_ms", self.timeout_ms, 500, MAX_TIMEOUT_MS)?,
        })
    }
}

async fn run_scan(plan: ScanPlan, progress: Option<ToolProgressCallback>) -> SecurityHeadersReport {
    let checklist = scan_checklist();
    let total = checklist.len() as u64;
    let mut completed = 0;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    let client = match Client::builder()
        .timeout(Duration::from_millis(plan.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return SecurityHeadersReport::failed(
                &plan,
                format!("failed to build HTTP client: {error}"),
            );
        }
    };

    let response = send_request(&client, &plan).await;
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    let observed = match response {
        Ok(observed) => observed,
        Err(error) => {
            return SecurityHeadersReport::failed(&plan, error);
        }
    };

    let mut findings = Vec::new();
    findings.extend(analyze_security_headers(
        &observed,
        plan.url.scheme() == "https",
    ));
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    findings.extend(analyze_cors(&observed));
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    findings.extend(analyze_cookies(&observed, plan.url.scheme() == "https"));
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    findings.extend(analyze_cache_policy(&observed));
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    findings.extend(analyze_server_fingerprint(&observed));
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    SecurityHeadersReport::completed(&plan, observed, findings)
}

async fn send_request(
    client: &Client,
    plan: &ScanPlan,
) -> std::result::Result<ObservedResponse, String> {
    let mut url = plan.url.clone();
    {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in &plan.query_params {
            pairs.append_pair(name, value);
        }
    }

    let mut request = client.request(plan.method.clone(), url.clone());
    let mut headers = plan.headers.clone();
    if !headers.contains_key(ORIGIN) {
        headers.insert(ORIGIN, HeaderValue::from_static(PROBE_ORIGIN));
    }
    request = request.headers(headers);

    if let Some(body) = &plan.body {
        request = if body.is_string() {
            request.body(body.as_str().unwrap_or_default().to_owned())
        } else {
            request.json(body)
        };
    }

    let response = request
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = response.headers().clone();
    let body_preview = response.text().await.unwrap_or_default();

    Ok(ObservedResponse {
        status,
        final_url,
        headers: flatten_headers(&headers),
        set_cookies: headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect(),
        body_preview: body_preview.chars().take(BODY_PREVIEW_LIMIT).collect(),
    })
}

fn analyze_security_headers(observed: &ObservedResponse, is_https: bool) -> Vec<HeaderFinding> {
    let mut findings = Vec::new();
    let headers = &observed.headers;

    if is_https && !headers.contains_key("strict-transport-security") {
        findings.push(HeaderFinding::medium(
            "missing_hsts",
            "Strict-Transport-Security is missing on an HTTPS response.",
            "Add HSTS after confirming the service is fully HTTPS-ready.",
        ));
    }
    if !headers.contains_key("content-security-policy") {
        findings.push(HeaderFinding::medium(
            "missing_csp",
            "Content-Security-Policy is missing.",
            "Define a CSP that restricts script, object, frame, and connection sources.",
        ));
    }
    if headers
        .get("x-content-type-options")
        .is_none_or(|value| !value.eq_ignore_ascii_case("nosniff"))
    {
        findings.push(HeaderFinding::low(
            "missing_x_content_type_options",
            "X-Content-Type-Options is missing or not set to nosniff.",
            "Set X-Content-Type-Options: nosniff.",
        ));
    }
    if !headers.contains_key("x-frame-options")
        && headers
            .get("content-security-policy")
            .is_none_or(|value| !value.to_ascii_lowercase().contains("frame-ancestors"))
    {
        findings.push(HeaderFinding::medium(
            "missing_frame_protection",
            "No X-Frame-Options header or CSP frame-ancestors directive was found.",
            "Set CSP frame-ancestors or X-Frame-Options to reduce clickjacking risk.",
        ));
    }
    if !headers.contains_key("referrer-policy") {
        findings.push(HeaderFinding::low(
            "missing_referrer_policy",
            "Referrer-Policy is missing.",
            "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
        ));
    }
    if !headers.contains_key("permissions-policy") {
        findings.push(HeaderFinding::low(
            "missing_permissions_policy",
            "Permissions-Policy is missing.",
            "Set Permissions-Policy to disable browser features the endpoint does not need.",
        ));
    }

    findings
}

fn analyze_cors(observed: &ObservedResponse) -> Vec<HeaderFinding> {
    let mut findings = Vec::new();
    let origin = observed
        .headers
        .get("access-control-allow-origin")
        .map(String::as_str);
    let credentials = observed
        .headers
        .get("access-control-allow-credentials")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    match (origin, credentials) {
        (Some("*"), true) => findings.push(HeaderFinding::high(
            "cors_wildcard_with_credentials",
            "CORS allows any origin while also allowing credentials.",
            "Do not combine Access-Control-Allow-Origin: * with credentialed requests.",
        )),
        (Some(value), true) if value == PROBE_ORIGIN => findings.push(HeaderFinding::medium(
            "cors_reflects_arbitrary_origin",
            "CORS reflected the probe Origin and allows credentials.",
            "Use an allowlist for trusted origins and reject arbitrary Origin values.",
        )),
        (Some("*"), false) => findings.push(HeaderFinding::low(
            "cors_wildcard_origin",
            "CORS allows any origin.",
            "Use a specific allowlist unless this endpoint intentionally serves public data.",
        )),
        (Some(value), false) if value == PROBE_ORIGIN => findings.push(HeaderFinding::low(
            "cors_reflects_probe_origin",
            "CORS reflected the probe Origin.",
            "Confirm this endpoint should be callable from arbitrary browser origins.",
        )),
        _ => {}
    }

    findings
}

fn analyze_cookies(observed: &ObservedResponse, is_https: bool) -> Vec<HeaderFinding> {
    let mut findings = Vec::new();
    for cookie in &observed.set_cookies {
        let lower = cookie.to_ascii_lowercase();
        let name = cookie.split('=').next().unwrap_or("cookie").trim();
        if !lower.contains("httponly") {
            findings.push(HeaderFinding::medium(
                "cookie_missing_httponly",
                format!("Set-Cookie `{name}` is missing HttpOnly."),
                "Add HttpOnly to session or authentication cookies.",
            ));
        }
        if is_https && !lower.contains("secure") {
            findings.push(HeaderFinding::medium(
                "cookie_missing_secure",
                format!("Set-Cookie `{name}` is missing Secure on an HTTPS response."),
                "Add Secure to cookies served over HTTPS.",
            ));
        }
        if !lower.contains("samesite=") {
            findings.push(HeaderFinding::low(
                "cookie_missing_samesite",
                format!("Set-Cookie `{name}` is missing SameSite."),
                "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.",
            ));
        }
    }

    findings
}

fn analyze_cache_policy(observed: &ObservedResponse) -> Vec<HeaderFinding> {
    let Some(value) = observed.headers.get("cache-control") else {
        return vec![HeaderFinding::low(
            "missing_cache_control",
            "Cache-Control is missing.",
            "Set Cache-Control deliberately; use no-store for sensitive responses.",
        )];
    };

    let lower = value.to_ascii_lowercase();
    if lower.contains("public") && !lower.contains("no-store") && !lower.contains("private") {
        return vec![HeaderFinding::low(
            "public_cache_control",
            "Cache-Control allows public caching.",
            "Confirm the response contains only public data or use private/no-store.",
        )];
    }

    Vec::new()
}

fn analyze_server_fingerprint(observed: &ObservedResponse) -> Vec<HeaderFinding> {
    let mut findings = Vec::new();
    for name in ["server", "x-powered-by"] {
        if let Some(value) = observed.headers.get(name) {
            findings.push(HeaderFinding::low(
                format!("server_fingerprint_{name}"),
                format!("Response exposes `{name}: {value}`."),
                "Avoid exposing precise server/framework versions when practical.",
            ));
        }
    }

    findings
}

#[derive(Debug, Clone, Serialize)]
struct SecurityHeadersReport {
    url: String,
    final_url: Option<String>,
    method: String,
    status: Option<u16>,
    risk_level: String,
    summary: String,
    sample_coverage: Vec<String>,
    attack_types: Vec<String>,
    remediation: Vec<String>,
    findings: Vec<HeaderFinding>,
    observed_headers: BTreeMap<String, String>,
    set_cookie_count: usize,
    body_preview: Option<String>,
    error: Option<String>,
    recommendations: Vec<String>,
}

impl SecurityHeadersReport {
    fn completed(
        plan: &ScanPlan,
        observed: ObservedResponse,
        findings: Vec<HeaderFinding>,
    ) -> Self {
        let risk_level = aggregate_risk(&findings).to_owned();
        let risky_count = findings.len();
        let sample_coverage = security_headers_sample_coverage(plan, &observed);
        let attack_types = security_headers_attack_types(&findings);
        let remediation = security_headers_remediation(&findings, &risk_level);
        Self {
            url: plan.url.to_string(),
            final_url: Some(observed.final_url),
            method: plan.method.to_string(),
            status: Some(observed.status),
            risk_level: risk_level.clone(),
            summary: format!(
                "HTTP security header scan completed: {risky_count} finding(s), overall risk {risk_level}."
            ),
            sample_coverage,
            attack_types,
            remediation,
            findings,
            observed_headers: observed.headers,
            set_cookie_count: observed.set_cookies.len(),
            body_preview: Some(observed.body_preview),
            error: None,
            recommendations: recommendations_for(&risk_level),
        }
    }

    fn failed(plan: &ScanPlan, error: String) -> Self {
        Self {
            url: plan.url.to_string(),
            final_url: None,
            method: plan.method.to_string(),
            status: None,
            risk_level: WARNING.to_owned(),
            summary: format!("HTTP security header scan failed: {error}"),
            sample_coverage: vec![format!(
                "Attempted baseline request: {} {}",
                plan.method, plan.url
            )],
            attack_types: vec!["security header coverage validation".to_owned()],
            remediation: vec![
                "Confirm the URL, method, headers, and network reachability before retrying."
                    .to_owned(),
            ],
            findings: Vec::new(),
            observed_headers: BTreeMap::new(),
            set_cookie_count: 0,
            body_preview: None,
            error: Some(error),
            recommendations: vec![
                "Confirm the URL, method, headers, and network reachability before retrying."
                    .to_owned(),
            ],
        }
    }

    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct HeaderFinding {
    kind: String,
    #[serde(rename = "risk_level")]
    risk: String,
    evidence: String,
    recommendation: String,
}

impl HeaderFinding {
    fn low(
        kind: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(kind, WARNING, evidence, recommendation)
    }

    fn medium(
        kind: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(kind, WARNING, evidence, recommendation)
    }

    fn high(
        kind: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(kind, DANGER, evidence, recommendation)
    }

    fn new(
        kind: impl Into<String>,
        risk: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            risk: risk.into(),
            evidence: evidence.into(),
            recommendation: recommendation.into(),
        }
    }
}

#[derive(Debug)]
struct ObservedResponse {
    status: u16,
    final_url: String,
    headers: BTreeMap<String, String>,
    set_cookies: Vec<String>,
    body_preview: String,
}

fn flatten_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut flattened = BTreeMap::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            flattened.insert(name.as_str().to_ascii_lowercase(), value.to_owned());
        }
    }
    flattened
}

fn security_headers_sample_coverage(plan: &ScanPlan, observed: &ObservedResponse) -> Vec<String> {
    vec![
        format!("Baseline request: {} {}", plan.method, plan.url),
        format!("Final URL after redirects: {}", observed.final_url),
        format!("HTTP status observed: {}", observed.status),
        format!("Observed {} response header(s).", observed.headers.len()),
        format!(
            "Observed {} Set-Cookie header(s).",
            observed.set_cookies.len()
        ),
        "Sent a controlled Origin probe to evaluate CORS behavior.".to_owned(),
        format!("Captured body preview up to {} bytes.", BODY_PREVIEW_LIMIT),
    ]
}

fn security_headers_attack_types(findings: &[HeaderFinding]) -> Vec<String> {
    let mut attack_types = Vec::new();
    for finding in findings {
        match finding.kind.as_str() {
            "missing_csp" => push_unique_string(&mut attack_types, "cross-site scripting"),
            "missing_x_frame_options" => push_unique_string(&mut attack_types, "clickjacking"),
            "missing_hsts" => {
                push_unique_string(&mut attack_types, "TLS downgrade / HTTPS stripping")
            }
            "missing_x_content_type_options" => {
                push_unique_string(&mut attack_types, "MIME sniffing")
            }
            "missing_referrer_policy" => {
                push_unique_string(&mut attack_types, "referrer information leakage")
            }
            "missing_permissions_policy" => {
                push_unique_string(&mut attack_types, "browser feature abuse")
            }
            "cors_wildcard_with_credentials" | "cors_reflects_probe_origin_with_credentials" => {
                push_unique_string(&mut attack_types, "credentialed CORS abuse")
            }
            "cors_wildcard" | "cors_reflects_probe_origin" => {
                push_unique_string(&mut attack_types, "overly broad CORS access")
            }
            "cookie_missing_httponly" => {
                push_unique_string(&mut attack_types, "session cookie theft via XSS")
            }
            "cookie_missing_secure" => {
                push_unique_string(&mut attack_types, "session cookie leakage over HTTP")
            }
            "cookie_missing_samesite" => {
                push_unique_string(&mut attack_types, "cross-site request forgery")
            }
            "cache_missing_policy" => {
                push_unique_string(&mut attack_types, "sensitive response caching")
            }
            kind if kind.starts_with("server_fingerprint_") => {
                push_unique_string(&mut attack_types, "technology fingerprinting")
            }
            kind => push_unique_string(&mut attack_types, kind),
        }
    }
    if attack_types.is_empty() {
        attack_types.push("HTTP security header baseline validation".to_owned());
    }
    attack_types
}

fn security_headers_remediation(findings: &[HeaderFinding], risk_level: &str) -> Vec<String> {
    let mut remediation = Vec::new();
    for finding in findings {
        push_unique_string(&mut remediation, &finding.recommendation);
    }
    for recommendation in recommendations_for(risk_level) {
        push_unique_string(&mut remediation, &recommendation);
    }
    remediation
}

fn push_unique_string(items: &mut Vec<String>, item: &str) {
    if !item.is_empty() && !items.iter().any(|existing| existing == item) {
        items.push(item.to_owned());
    }
}

fn aggregate_risk(findings: &[HeaderFinding]) -> &'static str {
    risk::max_label(findings.iter().map(|finding| finding.risk.as_str()))
}

fn recommendations_for(risk_level: &str) -> Vec<String> {
    let mut recommendations = vec![
        "Set a deliberate baseline of security headers at the gateway or application layer."
            .to_owned(),
        "Review CORS and cookie settings against the endpoint's real browser access requirements."
            .to_owned(),
    ];

    if risk_level != NORMAL {
        recommendations.push(
            "Prioritize dangerous and warning findings before exposing this endpoint outside trusted networks."
                .to_owned(),
        );
    }

    recommendations
}

fn scan_checklist() -> Vec<String> {
    vec![
        "Baseline request".to_owned(),
        "Security headers".to_owned(),
        "CORS policy".to_owned(),
        "Cookie attributes".to_owned(),
        "Cache policy".to_owned(),
        "Server fingerprint".to_owned(),
    ]
}

fn emit_progress(
    progress: Option<&ToolProgressCallback>,
    completed: u64,
    total: u64,
    checklist: &[String],
) {
    let Some(progress) = progress else {
        return;
    };

    let checked_index = completed.saturating_sub(1) as usize;
    let checked_item = checklist.get(checked_index).cloned().unwrap_or_default();
    let items: Vec<_> = checklist
        .iter()
        .enumerate()
        .map(|(index, label)| {
            json!({
                "label": label,
                "checked": (index as u64) < completed
            })
        })
        .collect();

    progress(
        ToolProgress::new(
            "http_security_headers_scan",
            format!("completed {completed}/{total}: {checked_item}"),
            completed,
            total,
        )
        .with_metadata(json!({
            "display_type": "checklist",
            "checked_item": checked_item,
            "checklist": items
        })),
    );
}

fn default_method() -> String {
    "GET".to_owned()
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn bounded(tool: &str, field: &str, value: u64, min: u64, max: u64) -> Result<u64> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(invalid(
            tool,
            format!("{field} must be between {min} and {max}"),
        ))
    }
}

fn invalid(tool: &str, message: impl Into<String>) -> ToolError {
    ToolError::InvalidInput {
        tool: tool.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolRegistry;

    #[test]
    fn detects_missing_security_headers() {
        let observed = ObservedResponse {
            status: 200,
            final_url: "https://example.test".to_owned(),
            headers: BTreeMap::new(),
            set_cookies: Vec::new(),
            body_preview: String::new(),
        };

        let findings = analyze_security_headers(&observed, true);

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "missing_hsts")
        );
        assert!(findings.iter().any(|finding| finding.kind == "missing_csp"));
    }

    #[test]
    fn detects_cors_wildcard_with_credentials() {
        let mut headers = BTreeMap::new();
        headers.insert("access-control-allow-origin".to_owned(), "*".to_owned());
        headers.insert(
            "access-control-allow-credentials".to_owned(),
            "true".to_owned(),
        );
        let observed = ObservedResponse {
            status: 200,
            final_url: "https://example.test".to_owned(),
            headers,
            set_cookies: Vec::new(),
            body_preview: String::new(),
        };

        let findings = analyze_cors(&observed);

        assert_eq!(findings[0].kind, "cors_wildcard_with_credentials");
        assert_eq!(findings[0].risk, DANGER);
    }

    #[test]
    fn builds_scan_checklist() {
        assert_eq!(
            scan_checklist(),
            vec![
                "Baseline request",
                "Security headers",
                "CORS policy",
                "Cookie attributes",
                "Cache policy",
                "Server fingerprint"
            ]
        );
    }

    #[test]
    fn rejects_unsupported_url_scheme() {
        let input = SecurityHeadersInput {
            url: "file:///tmp/test".to_owned(),
            method: "GET".to_owned(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };

        assert!(input.into_plan("http_security_headers_scan").is_err());
    }

    #[tokio::test]
    async fn registry_includes_http_security_headers_scan() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("http_security_headers_scan"));
        assert!(registry.spec("http_security_headers_scan").is_some());
    }
}
