use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
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
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const CONTEXT_PREVIEW_BYTES: usize = 120;

#[derive(Debug, Clone, Copy)]
pub struct XssRiskScanTool;

#[async_trait]
impl ToolHandler for XssRiskScanTool {
    fn name(&self) -> &'static str {
        "xss_risk_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Probe an authorized HTTP endpoint for reflected or stored XSS risk using unique markers and low-impact browser payloads. Requires at least one testable query, body, or header input point.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint to probe. Query parameters in the URL are treated as testable input points."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method.",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers, such as Cookie or Authorization for an authorized test session.",
                        "additionalProperties": { "type": "string" }
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Additional query parameters to include and potentially test.",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "description": "Optional JSON/form body. Flat object fields are testable input points."
                    },
                    "body_format": {
                        "type": "string",
                        "description": "How to send object bodies. Use form for HTML/PHP forms, json for APIs, or auto to infer.",
                        "enum": ["auto", "json", "form"],
                        "default": "auto"
                    },
                    "injectable_fields": {
                        "type": "array",
                        "description": "Optional field names to test. If omitted, existing query/body fields are tested.",
                        "items": { "type": "string" }
                    },
                    "injectable_headers": {
                        "type": "array",
                        "description": "Optional request header names to test as XSS input points, such as Referer, User-Agent, or X-Forwarded-For.",
                        "items": { "type": "string" }
                    },
                    "verification_urls": {
                        "type": "array",
                        "description": "Optional pages to fetch after probes to look for stored XSS reflection.",
                        "items": { "type": "string" }
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

impl XssRiskScanTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: XssRiskInput =
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
struct XssRiskInput {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    query_params: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    body_format: BodyFormat,
    #[serde(default)]
    injectable_fields: Vec<String>,
    #[serde(default)]
    injectable_headers: Vec<String>,
    #[serde(default)]
    verification_urls: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BodyFormat {
    #[default]
    Auto,
    Json,
    Form,
}

#[derive(Debug, Clone)]
struct ScanPlan {
    url: Url,
    method: Method,
    headers: HeaderMap,
    query_values: BTreeMap<String, String>,
    body_values: BTreeMap<String, String>,
    raw_body: Option<String>,
    body_format: BodyFormat,
    input_points: Vec<InputPoint>,
    verification_urls: Vec<Url>,
    timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InputPoint {
    location: InputLocation,
    name: String,
    baseline_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InputLocation {
    Query,
    Header,
    Body,
}

impl XssRiskInput {
    fn into_plan(self, tool: &str) -> Result<ScanPlan> {
        let mut url = Url::parse(&self.url).map_err(|error| invalid(tool, error.to_string()))?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => return Err(invalid(tool, format!("unsupported URL scheme: {scheme}"))),
        }

        let method = Method::from_str(&self.method.to_ascii_uppercase())
            .map_err(|error| invalid(tool, error.to_string()))?;
        if !matches!(
            method,
            Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return Err(invalid(tool, format!("unsupported HTTP method: {method}")));
        }

        let mut query_values = url
            .query_pairs()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        for (name, value) in self.query_params {
            query_values.insert(name, value);
        }
        url.set_query(None);

        let mut body_values = BTreeMap::new();
        let mut raw_body = None;
        if let Some(body) = self.body {
            match body {
                Value::Object(object) => {
                    for (name, value) in object {
                        body_values.insert(name, value_to_string(&value));
                    }
                }
                Value::String(raw) => raw_body = Some(raw),
                value => raw_body = Some(value.to_string()),
            }
        }

        let mut headers = HeaderMap::new();
        for (name, value) in self.headers {
            let name =
                HeaderName::from_str(&name).map_err(|error| invalid(tool, error.to_string()))?;
            let value =
                HeaderValue::from_str(&value).map_err(|error| invalid(tool, error.to_string()))?;
            headers.insert(name, value);
        }

        let verification_urls = self
            .verification_urls
            .into_iter()
            .map(|raw| Url::parse(&raw).map_err(|error| invalid(tool, error.to_string())))
            .collect::<Result<Vec<_>>>()?;

        let input_points = input_points_for(
            tool,
            &method,
            &headers,
            &query_values,
            &body_values,
            raw_body.as_ref(),
            &self.injectable_fields,
            &self.injectable_headers,
        )?;

        Ok(ScanPlan {
            url,
            method,
            headers,
            query_values,
            body_values,
            raw_body,
            body_format: self.body_format,
            input_points,
            verification_urls,
            timeout_ms: bounded(tool, "timeout_ms", self.timeout_ms, 500, MAX_TIMEOUT_MS)?,
        })
    }
}

fn input_points_for(
    tool: &str,
    method: &Method,
    headers: &HeaderMap,
    query_values: &BTreeMap<String, String>,
    body_values: &BTreeMap<String, String>,
    raw_body: Option<&String>,
    injectable_fields: &[String],
    injectable_headers: &[String],
) -> Result<Vec<InputPoint>> {
    let mut points = Vec::new();

    if injectable_fields.is_empty() {
        for (name, value) in query_values {
            points.push(InputPoint {
                location: InputLocation::Query,
                name: name.clone(),
                baseline_value: value.clone(),
            });
        }
        for (name, value) in body_values {
            points.push(InputPoint {
                location: InputLocation::Body,
                name: name.clone(),
                baseline_value: value.clone(),
            });
        }
    } else {
        for field in injectable_fields {
            if let Some(value) = query_values.get(field) {
                points.push(InputPoint {
                    location: InputLocation::Query,
                    name: field.clone(),
                    baseline_value: value.clone(),
                });
            } else if let Some(value) = body_values.get(field) {
                points.push(InputPoint {
                    location: InputLocation::Body,
                    name: field.clone(),
                    baseline_value: value.clone(),
                });
            } else if method == Method::GET {
                points.push(InputPoint {
                    location: InputLocation::Query,
                    name: field.clone(),
                    baseline_value: String::new(),
                });
            } else if raw_body.is_none() {
                points.push(InputPoint {
                    location: InputLocation::Body,
                    name: field.clone(),
                    baseline_value: String::new(),
                });
            }
        }
    }
    for header in injectable_headers {
        if let Some(input_point) = header_input_point(tool, headers, header)? {
            points.push(input_point);
        }
    }

    if points.is_empty() {
        return Err(invalid(
            tool,
            "xss_risk_scan needs at least one testable input point: query params in the URL, query_params, object body fields, injectable_fields, or injectable_headers",
        ));
    }
    Ok(points)
}

fn header_input_point(
    tool: &str,
    headers: &HeaderMap,
    raw_name: &str,
) -> Result<Option<InputPoint>> {
    let raw_name = raw_name.trim();
    if raw_name.is_empty() {
        return Ok(None);
    }
    let name = HeaderName::from_str(raw_name).map_err(|error| {
        invalid(
            tool,
            format!("invalid injectable header {raw_name}: {error}"),
        )
    })?;
    let baseline_value = headers
        .get(&name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    Ok(Some(InputPoint {
        location: InputLocation::Header,
        name: name.as_str().to_owned(),
        baseline_value,
    }))
}

async fn run_scan(plan: ScanPlan, progress: Option<ToolProgressCallback>) -> XssRiskReport {
    let checklist = scan_checklist(&plan.input_points, !plan.verification_urls.is_empty());
    let total = checklist.len() as u64;
    let mut completed = 0;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    let client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(plan.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return XssRiskReport::failed(&plan, format!("failed to build client: {error}"));
        }
    };

    let baseline = send_request(&client, &plan, None).await;
    completed += 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    let baseline = match baseline {
        Ok(response) => response,
        Err(error) => return XssRiskReport::failed(&plan, error),
    };

    let mut probes = Vec::new();
    let mut findings = Vec::new();
    for input_point in &plan.input_points {
        let marker = unique_marker(input_point);
        let marker_response = send_request(
            &client,
            &plan,
            Some(FieldProbe {
                input_point,
                value: marker.clone(),
            }),
        )
        .await;
        completed += 1;
        emit_progress(progress.as_ref(), completed.min(total), total, &checklist);

        match marker_response {
            Ok(response) => {
                let probe = analyze_marker_probe(input_point, &marker, &response);
                probes.push(probe);
            }
            Err(error) => findings.push(XssFinding::low(
                "probe_request_error",
                input_point,
                "request",
                format!("Marker probe failed for `{}`: {error}", input_point.name),
                "Confirm method, auth headers, CSRF requirements, and target reachability before retesting.",
            )),
        }

        for payload in xss_payloads(&marker) {
            let payload_response = send_request(
                &client,
                &plan,
                Some(FieldProbe {
                    input_point,
                    value: payload.value.clone(),
                }),
            )
            .await;
            completed += 1;
            emit_progress(progress.as_ref(), completed.min(total), total, &checklist);

            match payload_response {
                Ok(response) => {
                    let probe = analyze_payload_probe(input_point, &marker, &payload, &response);
                    findings.extend(findings_from_probe(input_point, &probe));
                    probes.push(probe);
                }
                Err(error) => findings.push(XssFinding::low(
                    "probe_request_error",
                    input_point,
                    "request",
                    format!(
                        "{} payload probe failed for `{}`: {error}",
                        payload.name, input_point.name
                    ),
                    "Confirm method, auth headers, CSRF requirements, and target reachability before retesting.",
                )),
            }
        }
    }

    if !plan.verification_urls.is_empty() {
        findings.extend(
            verify_stored_reflection(&client, &plan, &plan.input_points)
                .await
                .unwrap_or_else(|error| {
                    vec![XssFinding::low(
                        "verification_request_error",
                        &plan.input_points[0],
                        "verification",
                        error,
                        "Confirm verification_urls are reachable and authenticated before retesting stored XSS.",
                    )]
                }),
        );
        completed += 1;
        emit_progress(progress.as_ref(), completed.min(total), total, &checklist);
    }

    XssRiskReport::completed(&plan, baseline, probes, findings)
}

#[derive(Debug)]
struct FieldProbe<'a> {
    input_point: &'a InputPoint,
    value: String,
}

async fn send_request(
    client: &Client,
    plan: &ScanPlan,
    probe: Option<FieldProbe<'_>>,
) -> std::result::Result<ObservedResponse, String> {
    let mut url = plan.url.clone();
    let mut query_values = plan.query_values.clone();
    let mut headers = plan.headers.clone();
    let mut body_values = plan.body_values.clone();
    let mut raw_body = plan.raw_body.clone();

    if let Some(probe) = probe {
        match probe.input_point.location {
            InputLocation::Query => {
                query_values.insert(probe.input_point.name.clone(), probe.value);
            }
            InputLocation::Header => {
                let name = HeaderName::from_str(&probe.input_point.name).map_err(|error| {
                    format!("invalid probe header {}: {error}", probe.input_point.name)
                })?;
                let value = HeaderValue::from_str(&probe.value).map_err(|error| {
                    format!(
                        "invalid probe header value for {}: {error}",
                        probe.input_point.name
                    )
                })?;
                headers.insert(name, value);
            }
            InputLocation::Body => {
                if raw_body.is_none() {
                    body_values.insert(probe.input_point.name.clone(), probe.value);
                }
            }
        }
    }

    {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in &query_values {
            pairs.append_pair(name, value);
        }
    }

    let mut request = client.request(plan.method.clone(), url);
    request = request.headers(headers);

    if !matches!(plan.method, Method::GET) {
        if let Some(raw) = raw_body.take() {
            request = request.body(raw);
        } else if !body_values.is_empty() {
            request = match resolved_body_format(plan) {
                BodyFormat::Json => request.json(&body_values),
                BodyFormat::Form | BodyFormat::Auto => request.form(&body_values),
            };
        }
    }

    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = flatten_headers(response.headers());
    let content_type = headers.get("content-type").cloned();
    let body_bytes = response.bytes().await.map_err(|error| error.to_string())?;
    let body = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(MAX_RESPONSE_BYTES)])
        .into_owned();

    Ok(ObservedResponse {
        status,
        final_url,
        headers,
        content_type,
        body,
    })
}

fn resolved_body_format(plan: &ScanPlan) -> BodyFormat {
    if plan.body_format != BodyFormat::Auto {
        return plan.body_format;
    }
    if let Some(content_type) = plan.headers.get(CONTENT_TYPE)
        && content_type
            .to_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("json")
    {
        return BodyFormat::Json;
    }
    BodyFormat::Form
}

async fn verify_stored_reflection(
    client: &Client,
    plan: &ScanPlan,
    input_points: &[InputPoint],
) -> std::result::Result<Vec<XssFinding>, String> {
    let mut findings = Vec::new();
    let markers = input_points
        .iter()
        .map(|input_point| (input_point, unique_marker(input_point)))
        .collect::<Vec<_>>();

    for verification_url in &plan.verification_urls {
        let mut request = client.get(verification_url.clone());
        request = request.headers(plan.headers.clone());
        let response = request.send().await.map_err(|error| error.to_string())?;
        let body_bytes = response.bytes().await.map_err(|error| error.to_string())?;
        let body = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(MAX_RESPONSE_BYTES)])
            .into_owned();

        for (input_point, marker) in &markers {
            if body.contains(marker) {
                findings.push(XssFinding::medium(
                    "stored_xss_candidate",
                    input_point,
                    "stored_reflection",
                    format!(
                        "`{}` marker appeared on verification page `{}` after probing.",
                        input_point.name, verification_url
                    ),
                    "Encode untrusted stored content on output and sanitize rich-text inputs with an allowlist policy.",
                ));
            }
        }
    }

    Ok(findings)
}

fn analyze_marker_probe(
    input_point: &InputPoint,
    marker: &str,
    observed: &ObservedResponse,
) -> XssProbe {
    let reflected = observed.body.contains(marker);
    let contexts = reflection_contexts(&observed.body, marker);
    XssProbe {
        field: input_point.name.clone(),
        location: input_point.location,
        probe_kind: "marker".to_owned(),
        payload_name: None,
        status: observed.status,
        final_url: observed.final_url.clone(),
        content_type: observed.content_type.clone(),
        reflected,
        executable_payload_reflected: false,
        encoded_payload_reflected: false,
        contexts,
    }
}

fn analyze_payload_probe(
    input_point: &InputPoint,
    marker: &str,
    payload: &XssPayload,
    observed: &ObservedResponse,
) -> XssProbe {
    let reflected = observed.body.contains(marker);
    let lower_body = observed.body.to_ascii_lowercase();
    let executable_payload_reflected = observed.body.contains(&payload.value)
        || (reflected && contains_executable_xss_pattern(&lower_body));
    let encoded_payload_reflected = lower_body.contains("&lt;svg")
        || lower_body.contains("&lt;img")
        || lower_body.contains("&lt;script")
        || observed.body.contains("&quot;&gt;")
        || observed.body.contains("&#34;&gt;");
    let contexts = reflection_contexts(&observed.body, marker);

    XssProbe {
        field: input_point.name.clone(),
        location: input_point.location,
        probe_kind: "payload".to_owned(),
        payload_name: Some(payload.name.to_owned()),
        status: observed.status,
        final_url: observed.final_url.clone(),
        content_type: observed.content_type.clone(),
        reflected,
        executable_payload_reflected,
        encoded_payload_reflected,
        contexts,
    }
}

fn contains_executable_xss_pattern(lower_body: &str) -> bool {
    (lower_body.contains("<svg") && lower_body.contains("onload="))
        || (lower_body.contains("<img") && lower_body.contains("onerror="))
        || (lower_body.contains("<script") && lower_body.contains("confirm(1)"))
        || lower_body.contains("onfocus=confirm(1)")
        || lower_body.contains("javascript:confirm(1)")
}

fn findings_from_probe(input_point: &InputPoint, probe: &XssProbe) -> Vec<XssFinding> {
    let mut findings = Vec::new();

    if probe.executable_payload_reflected {
        let context = probe
            .contexts
            .first()
            .map(|context| context.context.as_str())
            .unwrap_or("html");
        findings.push(XssFinding::high(
            "reflected_xss_candidate",
            input_point,
            context,
            format!(
                "`{}` reflected executable XSS probe `{}` without output encoding.",
                input_point.name,
                probe.payload_name.as_deref().unwrap_or("payload")
            ),
            "Contextually encode untrusted output, sanitize HTML with an allowlist sanitizer, and deploy a restrictive Content-Security-Policy.",
        ));
    } else if probe.reflected && !probe.encoded_payload_reflected {
        findings.push(XssFinding::medium(
            "unencoded_reflection",
            input_point,
            "reflection",
            format!(
                "`{}` reflected the marker and did not show clear HTML-encoded payload evidence.",
                input_point.name
            ),
            "Review the rendering context and add output encoding for this sink before treating the field as safe.",
        ));
    } else if probe.reflected {
        findings.push(XssFinding::low(
            "encoded_reflection",
            input_point,
            "reflection",
            format!(
                "`{}` reflected controlled input, but payload characters appeared encoded.",
                input_point.name
            ),
            "Keep contextual output encoding in place and add regression tests for this field.",
        ));
    }

    findings
}

fn reflection_contexts(body: &str, marker: &str) -> Vec<ReflectionContext> {
    let mut contexts = Vec::new();
    if marker.is_empty() {
        return contexts;
    }

    for (index, _) in body.match_indices(marker).take(5) {
        let start = floor_char_boundary(body, index.saturating_sub(CONTEXT_PREVIEW_BYTES));
        let end = ceil_char_boundary(
            body,
            (index + marker.len() + CONTEXT_PREVIEW_BYTES).min(body.len()),
        );
        let preview = body[start..end].replace('\n', "\\n");
        contexts.push(ReflectionContext {
            context: classify_context(&body[..index]),
            preview,
        });
    }
    contexts
}

fn floor_char_boundary(value: &str, index: usize) -> usize {
    let mut index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(value: &str, index: usize) -> usize {
    let mut index = index.min(value.len());
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn classify_context(before: &str) -> String {
    let lower = before.to_ascii_lowercase();
    let last_script_open = lower.rfind("<script");
    let last_script_close = lower.rfind("</script");
    if last_script_open.is_some() && last_script_open > last_script_close {
        return "script".to_owned();
    }

    let last_lt = lower.rfind('<');
    let last_gt = lower.rfind('>');
    if last_lt.is_some() && last_lt > last_gt {
        let tag_fragment = &lower[last_lt.unwrap_or(0)..];
        if tag_fragment.contains("href=")
            || tag_fragment.contains("src=")
            || tag_fragment.contains("action=")
        {
            return "url_attribute".to_owned();
        }
        if tag_fragment.contains('=') {
            return "html_attribute".to_owned();
        }
        return "html_tag".to_owned();
    }

    "html_text".to_owned()
}

#[derive(Debug, Clone, Serialize)]
struct XssRiskReport {
    url: String,
    method: String,
    risk_level: String,
    summary: String,
    sample_coverage: Vec<String>,
    attack_types: Vec<String>,
    remediation: Vec<String>,
    tested_fields: Vec<InputPoint>,
    probes: Vec<XssProbe>,
    findings: Vec<XssFinding>,
    baseline: Option<BaselineObservation>,
    error: Option<String>,
}

impl XssRiskReport {
    fn completed(
        plan: &ScanPlan,
        baseline: ObservedResponse,
        probes: Vec<XssProbe>,
        findings: Vec<XssFinding>,
    ) -> Self {
        let risk_level = aggregate_risk(&findings).to_owned();
        let risky_fields = findings
            .iter()
            .filter(|finding| !risk::is_normal(&finding.risk))
            .map(|finding| finding.field.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        let sample_coverage = xss_sample_coverage(plan, &baseline, &probes);
        let attack_types = xss_attack_types(&findings);
        let remediation = xss_remediation(&findings, &risk_level);
        Self {
            url: plan.url.to_string(),
            method: plan.method.to_string(),
            risk_level: risk_level.clone(),
            summary: format!(
                "XSS risk scan completed: {risky_fields} risky field(s), {} finding(s), overall risk {risk_level}.",
                findings.len()
            ),
            sample_coverage,
            attack_types,
            remediation,
            tested_fields: plan.input_points.clone(),
            probes,
            findings,
            baseline: Some(BaselineObservation {
                status: baseline.status,
                final_url: baseline.final_url,
                content_type: baseline.content_type,
                body_length: baseline.body.len(),
            }),
            error: None,
        }
    }

    fn failed(plan: &ScanPlan, error: String) -> Self {
        Self {
            url: plan.url.to_string(),
            method: plan.method.to_string(),
            risk_level: WARNING.to_owned(),
            summary: format!("XSS risk scan failed: {error}"),
            sample_coverage: vec![format!("Attempted baseline request: {} {}", plan.method, plan.url)],
            attack_types: vec!["XSS scan coverage validation".to_owned()],
            remediation: vec![
                "Confirm URL, method, auth headers, CSRF requirements, and testable fields before retrying.".to_owned(),
            ],
            tested_fields: plan.input_points.clone(),
            probes: Vec::new(),
            findings: Vec::new(),
            baseline: None,
            error: Some(error),
        }
    }

    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct BaselineObservation {
    status: u16,
    final_url: String,
    content_type: Option<String>,
    body_length: usize,
}

#[derive(Debug, Clone, Serialize)]
struct XssProbe {
    field: String,
    location: InputLocation,
    probe_kind: String,
    payload_name: Option<String>,
    status: u16,
    final_url: String,
    content_type: Option<String>,
    reflected: bool,
    executable_payload_reflected: bool,
    encoded_payload_reflected: bool,
    contexts: Vec<ReflectionContext>,
}

#[derive(Debug, Clone, Serialize)]
struct ReflectionContext {
    context: String,
    preview: String,
}

#[derive(Debug, Clone, Serialize)]
struct XssFinding {
    category: String,
    #[serde(rename = "risk_level")]
    risk: String,
    field: String,
    location: InputLocation,
    context: String,
    evidence: String,
    recommendation: String,
}

impl XssFinding {
    fn low(
        category: impl Into<String>,
        input_point: &InputPoint,
        context: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(
            category,
            NORMAL,
            input_point,
            context,
            evidence,
            recommendation,
        )
    }

    fn medium(
        category: impl Into<String>,
        input_point: &InputPoint,
        context: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(
            category,
            WARNING,
            input_point,
            context,
            evidence,
            recommendation,
        )
    }

    fn high(
        category: impl Into<String>,
        input_point: &InputPoint,
        context: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self::new(
            category,
            DANGER,
            input_point,
            context,
            evidence,
            recommendation,
        )
    }

    fn new(
        category: impl Into<String>,
        risk: impl Into<String>,
        input_point: &InputPoint,
        context: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            category: category.into(),
            risk: risk.into(),
            field: input_point.name.clone(),
            location: input_point.location,
            context: context.into(),
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
    content_type: Option<String>,
    body: String,
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

fn xss_sample_coverage(
    plan: &ScanPlan,
    baseline: &ObservedResponse,
    probes: &[XssProbe],
) -> Vec<String> {
    let mut coverage = vec![
        format!("Baseline request: {} {}", plan.method, plan.url),
        format!("Final baseline URL after redirects: {}", baseline.final_url),
        format!("Baseline HTTP status: {}", baseline.status),
        format!(
            "Baseline response headers observed: {}",
            baseline.headers.len()
        ),
        format!("Tested {} input field(s).", plan.input_points.len()),
        format!("Executed {} marker/payload probe request(s).", probes.len()),
    ];
    if !plan.verification_urls.is_empty() {
        coverage.push(format!(
            "Fetched {} verification page(s) for stored-reflection signals.",
            plan.verification_urls.len()
        ));
    }
    coverage
}

fn xss_attack_types(findings: &[XssFinding]) -> Vec<String> {
    let mut attack_types = Vec::new();
    for finding in findings {
        match finding.category.as_str() {
            "reflected_xss_candidate" => push_unique_string(&mut attack_types, "reflected XSS"),
            "stored_xss_candidate" => push_unique_string(&mut attack_types, "stored XSS"),
            "unencoded_reflection" => {
                push_unique_string(&mut attack_types, "unsafe output reflection")
            }
            "encoded_reflection" => {
                push_unique_string(&mut attack_types, "XSS regression coverage")
            }
            category => push_unique_string(&mut attack_types, category),
        }
    }
    if attack_types.is_empty() {
        attack_types.push("XSS probe coverage validation".to_owned());
    }
    attack_types
}

fn xss_remediation(findings: &[XssFinding], risk_level: &str) -> Vec<String> {
    let mut remediation = Vec::new();
    for finding in findings {
        push_unique_string(&mut remediation, &finding.recommendation);
    }
    push_unique_string(
        &mut remediation,
        "Apply context-aware output encoding for HTML text, attributes, JavaScript, CSS, and URL contexts.",
    );
    push_unique_string(
        &mut remediation,
        "Sanitize any allowed rich HTML with an allowlist sanitizer and add regression tests for each reflected/stored field.",
    );
    if risk_level != NORMAL {
        push_unique_string(
            &mut remediation,
            "Add or tighten Content-Security-Policy as defense in depth after fixing the output encoding bug.",
        );
    }
    remediation
}

fn push_unique_string(items: &mut Vec<String>, item: &str) {
    if !item.is_empty() && !items.iter().any(|existing| existing == item) {
        items.push(item.to_owned());
    }
}

fn aggregate_risk(findings: &[XssFinding]) -> &'static str {
    risk::max_label(findings.iter().map(|finding| finding.risk.as_str()))
}

fn scan_checklist(input_points: &[InputPoint], has_verification: bool) -> Vec<String> {
    let mut checklist = vec!["Baseline request".to_owned()];
    for input_point in input_points {
        checklist.push(format!("{}: marker reflection probe", input_point.name));
        for payload in xss_payloads("marker") {
            checklist.push(format!("{}: {} XSS probe", input_point.name, payload.name));
        }
    }
    if has_verification {
        checklist.push("Stored reflection verification".to_owned());
    }
    checklist
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

    let checked_item = checklist
        .get(completed.saturating_sub(1) as usize)
        .cloned()
        .unwrap_or_default();
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
            "xss_risk_scan",
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

fn unique_marker(input_point: &InputPoint) -> String {
    format!("spa-xss-{}", sanitize_marker(&input_point.name))
}

fn sanitize_marker(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if output.is_empty() {
        output = "field".to_owned();
    }
    output
}

#[derive(Debug, Clone)]
struct XssPayload {
    name: &'static str,
    value: String,
}

fn xss_payloads(marker: &str) -> Vec<XssPayload> {
    vec![
        XssPayload {
            name: "svg_event",
            value: format!("{marker}\"><svg/onload=confirm(1)>"),
        },
        XssPayload {
            name: "img_event",
            value: format!("{marker}\"><img src=x onerror=confirm(1)>"),
        },
        XssPayload {
            name: "mixed_case_script",
            value: format!("{marker}\"><ScRiPt>confirm(1)</ScRiPt>"),
        },
        XssPayload {
            name: "attribute_event",
            value: format!("{marker}\" autofocus onfocus=confirm(1) x=\""),
        },
        XssPayload {
            name: "javascript_url",
            value: format!("{marker}javascript:confirm(1)"),
        },
    ]
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(_) | Value::Bool(_) => value.to_string(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
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
    fn builds_scan_checklist_for_each_field() {
        let fields = vec![
            InputPoint {
                location: InputLocation::Query,
                name: "q".to_owned(),
                baseline_value: "test".to_owned(),
            },
            InputPoint {
                location: InputLocation::Body,
                name: "comment".to_owned(),
                baseline_value: "hi".to_owned(),
            },
        ];

        assert_eq!(
            scan_checklist(&fields, true),
            vec![
                "Baseline request",
                "q: marker reflection probe",
                "q: svg_event XSS probe",
                "q: img_event XSS probe",
                "q: mixed_case_script XSS probe",
                "q: attribute_event XSS probe",
                "q: javascript_url XSS probe",
                "comment: marker reflection probe",
                "comment: svg_event XSS probe",
                "comment: img_event XSS probe",
                "comment: mixed_case_script XSS probe",
                "comment: attribute_event XSS probe",
                "comment: javascript_url XSS probe",
                "Stored reflection verification",
            ]
        );
    }

    #[test]
    fn classifies_reflection_contexts() {
        assert_eq!(classify_context("<html><body>Hello "), "html_text");
        assert_eq!(classify_context("<input value=\""), "html_attribute");
        assert_eq!(classify_context("<a href=\""), "url_attribute");
        assert_eq!(classify_context("<script>const x = '"), "script");
    }

    #[test]
    fn reflection_context_preview_handles_multibyte_boundaries() {
        let marker = "spa-xss-field";
        let prefix = format!("{}{}", "成", "a".repeat(118));
        let suffix = format!("{}{}z", "a".repeat(119), "成");
        let body = format!("<html><body>{prefix}{marker}{suffix}</body></html>");

        let contexts = reflection_contexts(&body, marker);

        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].context, "html_text");
        assert!(contexts[0].preview.contains(marker));
        assert!(contexts[0].preview.contains("成"));
    }

    #[test]
    fn detects_executable_payload_reflection() {
        let input_point = InputPoint {
            location: InputLocation::Query,
            name: "q".to_owned(),
            baseline_value: "test".to_owned(),
        };
        let marker = unique_marker(&input_point);
        let payload = xss_payloads(&marker)
            .into_iter()
            .find(|payload| payload.name == "svg_event")
            .expect("svg payload should exist");
        let observed = ObservedResponse {
            status: 200,
            final_url: "https://target.example/search".to_owned(),
            headers: BTreeMap::new(),
            content_type: Some("text/html".to_owned()),
            body: format!("<html><body>{}</body></html>", payload.value),
        };

        let probe = analyze_payload_probe(&input_point, &marker, &payload, &observed);

        assert!(probe.reflected);
        assert!(probe.executable_payload_reflected);
        assert_eq!(probe.contexts[0].context, "html_text");
    }

    #[test]
    fn detects_dvwa_high_style_script_filter_bypass() {
        let input_point = InputPoint {
            location: InputLocation::Query,
            name: "name".to_owned(),
            baseline_value: "test".to_owned(),
        };
        let marker = unique_marker(&input_point);
        let payload = xss_payloads(&marker)
            .into_iter()
            .find(|payload| payload.name == "img_event")
            .expect("img payload should exist");
        let filtered = dvwa_high_script_filter(&payload.value);
        let observed = ObservedResponse {
            status: 200,
            final_url: "https://lab.example/vulnerable/xss_r/?name=probe".to_owned(),
            headers: BTreeMap::new(),
            content_type: Some("text/html".to_owned()),
            body: format!("Hello {filtered}"),
        };

        let probe = analyze_payload_probe(&input_point, &marker, &payload, &observed);
        let findings = findings_from_probe(&input_point, &probe);

        assert!(probe.executable_payload_reflected);
        assert!(findings.iter().any(|finding| finding.risk == DANGER));
    }

    #[test]
    fn builds_header_input_points_from_injectable_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Referer".to_owned(),
            "https://source.example/page".to_owned(),
        );
        let input = XssRiskInput {
            url: "https://target.example/echo".to_owned(),
            method: "GET".to_owned(),
            headers,
            query_params: BTreeMap::new(),
            body: None,
            body_format: BodyFormat::Auto,
            injectable_fields: Vec::new(),
            injectable_headers: vec!["Referer".to_owned()],
            verification_urls: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };

        let plan = input.into_plan("xss_risk_scan").expect("plan should build");

        assert_eq!(
            plan.input_points,
            vec![InputPoint {
                location: InputLocation::Header,
                name: "referer".to_owned(),
                baseline_value: "https://source.example/page".to_owned(),
            }]
        );
    }

    fn dvwa_high_script_filter(value: &str) -> String {
        value
            .replace("<script", "")
            .replace("<SCRIPT", "")
            .replace("<ScRiPt", "")
            .replace("</script>", "")
            .replace("</SCRIPT>", "")
            .replace("</ScRiPt>", "")
    }

    #[test]
    fn rejects_bare_url_without_input_points() {
        let input = XssRiskInput {
            url: "https://target.example/search".to_owned(),
            method: "GET".to_owned(),
            headers: HashMap::new(),
            query_params: BTreeMap::new(),
            body: None,
            body_format: BodyFormat::Auto,
            injectable_fields: Vec::new(),
            injectable_headers: Vec::new(),
            verification_urls: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };

        let result = input.into_plan("xss_risk_scan");

        assert!(matches!(result, Err(ToolError::InvalidInput { .. })));
    }

    #[test]
    fn registry_includes_xss_scan_tool() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("xss_risk_scan"));
    }
}
