use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolProgress, ToolProgressCallback,
    ToolSpec,
};

const DEFAULT_DURATION_SECS: u64 = 60;
const DEFAULT_REQUESTS_PER_MINUTE: u64 = 600;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const MAX_DURATION_SECS: u64 = 300;
const MAX_REQUESTS_PER_MINUTE: u64 = 60_000;
const MAX_CONCURRENCY: usize = 512;
const MAX_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy)]
pub struct HttpLoadTestTool;

#[async_trait]
impl ToolHandler for HttpLoadTestTool {
    fn name(&self) -> &'static str {
        "http_load_test"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Run a paced HTTP load test against a single endpoint and return latency, status, and error metrics.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint to test."
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
                    "body": {
                        "description": "Optional request body. Objects and arrays are sent as JSON; strings are sent as raw text."
                    },
                    "duration_secs": {
                        "type": "integer",
                        "description": "How long to schedule requests. Maximum 300.",
                        "minimum": 1,
                        "maximum": MAX_DURATION_SECS,
                        "default": DEFAULT_DURATION_SECS
                    },
                    "requests_per_minute": {
                        "type": "integer",
                        "description": "Target request rate. Maximum 60000.",
                        "minimum": 1,
                        "maximum": MAX_REQUESTS_PER_MINUTE,
                        "default": DEFAULT_REQUESTS_PER_MINUTE
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Maximum in-flight requests. Maximum 512.",
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                        "default": DEFAULT_CONCURRENCY
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Per-request timeout in milliseconds. Maximum 60000.",
                        "minimum": 100,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS
                    },
                    "success_statuses": {
                        "type": "array",
                        "description": "HTTP status codes counted as successful. Defaults to 200-399.",
                        "items": {
                            "type": "integer",
                            "minimum": 100,
                            "maximum": 599
                        }
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

impl HttpLoadTestTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: LoadTestInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;
        let plan = input.into_plan(self.name())?;
        let metrics = run_load_test(plan, progress).await;
        let metadata = serde_json::to_value(&metrics).map_err(|error| ToolError::Execution {
            tool: self.name().to_owned(),
            message: error.to_string(),
        })?;

        Ok(ToolOutput::text(call.id, metrics.summary()).with_metadata(metadata))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct LoadTestInput {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default = "default_duration_secs")]
    duration_secs: u64,
    #[serde(default = "default_requests_per_minute")]
    requests_per_minute: u64,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    success_statuses: Option<Vec<u16>>,
}

#[derive(Clone)]
struct LoadTestPlan {
    url: Url,
    method: Method,
    headers: HeaderMap,
    body: Option<Value>,
    duration_secs: u64,
    requests_per_minute: u64,
    concurrency: usize,
    timeout_ms: u64,
    success_statuses: Vec<u16>,
}

impl LoadTestInput {
    fn into_plan(self, tool: &str) -> Result<LoadTestPlan> {
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

        let success_statuses = self
            .success_statuses
            .unwrap_or_else(|| (200..=399).collect());
        if success_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
        {
            return Err(invalid(
                tool,
                "success_statuses must only contain HTTP status codes from 100 to 599",
            ));
        }

        Ok(LoadTestPlan {
            url,
            method,
            headers,
            body: self.body,
            duration_secs: bounded(
                tool,
                "duration_secs",
                self.duration_secs,
                1,
                MAX_DURATION_SECS,
            )?,
            requests_per_minute: bounded(
                tool,
                "requests_per_minute",
                self.requests_per_minute,
                1,
                MAX_REQUESTS_PER_MINUTE,
            )?,
            concurrency: bounded_usize(tool, "concurrency", self.concurrency, 1, MAX_CONCURRENCY)?,
            timeout_ms: bounded(tool, "timeout_ms", self.timeout_ms, 100, MAX_TIMEOUT_MS)?,
            success_statuses,
        })
    }
}

async fn run_load_test(
    plan: LoadTestPlan,
    progress: Option<ToolProgressCallback>,
) -> LoadTestMetrics {
    let total_planned =
        ((plan.requests_per_minute as f64 * plan.duration_secs as f64) / 60.0).ceil() as u64;
    let total_planned = total_planned.max(1);
    let client = Client::builder()
        .timeout(Duration::from_millis(plan.timeout_ms))
        .build()
        .unwrap_or_else(|_| Client::new());
    let started_at = Instant::now();
    let interval = Duration::from_nanos((60_000_000_000u64 / plan.requests_per_minute).max(1));
    let mut tasks = JoinSet::new();
    let mut outcomes = Vec::with_capacity(total_planned as usize);
    let mut scheduled_requests = 0;
    let mut last_progress_at = started_at;

    emit_load_test_progress(
        progress.as_ref(),
        total_planned,
        scheduled_requests,
        tasks.len(),
        &outcomes,
    );

    for index in 0..total_planned {
        while tasks.len() >= plan.concurrency {
            if let Some(outcome) = join_next(&mut tasks).await {
                outcomes.push(outcome);
            }
            if last_progress_at.elapsed() >= Duration::from_secs(5) {
                emit_load_test_progress(
                    progress.as_ref(),
                    total_planned,
                    scheduled_requests,
                    tasks.len(),
                    &outcomes,
                );
                last_progress_at = Instant::now();
            }
        }

        let scheduled_at = started_at + interval.mul_f64(index as f64);
        sleep_until(scheduled_at).await;

        let request_plan = plan.clone();
        let request_client = client.clone();
        tasks.spawn(async move { send_once(request_client, request_plan).await });
        scheduled_requests += 1;

        if last_progress_at.elapsed() >= Duration::from_secs(5) {
            emit_load_test_progress(
                progress.as_ref(),
                total_planned,
                scheduled_requests,
                tasks.len(),
                &outcomes,
            );
            last_progress_at = Instant::now();
        }
    }

    while let Some(outcome) = join_next(&mut tasks).await {
        outcomes.push(outcome);
        if last_progress_at.elapsed() >= Duration::from_secs(5) {
            emit_load_test_progress(
                progress.as_ref(),
                total_planned,
                scheduled_requests,
                tasks.len(),
                &outcomes,
            );
            last_progress_at = Instant::now();
        }
    }

    emit_load_test_progress(
        progress.as_ref(),
        total_planned,
        scheduled_requests,
        tasks.len(),
        &outcomes,
    );

    LoadTestMetrics::from_outcomes(
        plan.url.to_string(),
        plan.method.to_string(),
        plan.duration_secs,
        plan.requests_per_minute,
        plan.concurrency,
        total_planned,
        started_at.elapsed(),
        outcomes,
    )
}

fn emit_load_test_progress(
    progress: Option<&ToolProgressCallback>,
    planned_requests: u64,
    scheduled_requests: u64,
    in_flight_requests: usize,
    outcomes: &[RequestOutcome],
) {
    let Some(progress) = progress else {
        return;
    };

    let completed_requests = outcomes.len() as u64;
    let failed_requests = outcomes.iter().filter(|outcome| !outcome.success).count() as u64;
    let message = format!(
        "{completed_requests}/{planned_requests} requests completed, {failed_requests} failed, {in_flight_requests} in-flight"
    );

    progress(
        ToolProgress::new(
            "http_load_test",
            message,
            completed_requests,
            planned_requests,
        )
        .with_metadata(json!({
            "planned_requests": planned_requests,
            "scheduled_requests": scheduled_requests,
            "completed_requests": completed_requests,
            "failed_requests": failed_requests,
            "in_flight_requests": in_flight_requests
        })),
    );
}

async fn join_next(tasks: &mut JoinSet<RequestOutcome>) -> Option<RequestOutcome> {
    tasks
        .join_next()
        .await
        .map(|result| result.unwrap_or_else(|error| RequestOutcome::error(error.to_string())))
}

async fn send_once(client: Client, plan: LoadTestPlan) -> RequestOutcome {
    let started = Instant::now();
    let mut request = client
        .request(plan.method.clone(), plan.url)
        .headers(plan.headers);

    if let Some(body) = plan.body {
        request = match body {
            Value::String(text) => request.body(text),
            other => request.json(&other),
        };
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            RequestOutcome {
                status: Some(status),
                success: plan.success_statuses.contains(&status),
                latency_ms: Some(started.elapsed().as_millis() as u64),
                error: None,
            }
        }
        Err(error) => RequestOutcome::error(error.to_string()),
    }
}

#[derive(Debug)]
struct RequestOutcome {
    status: Option<u16>,
    success: bool,
    latency_ms: Option<u64>,
    error: Option<String>,
}

impl RequestOutcome {
    fn error(error: String) -> Self {
        Self {
            status: None,
            success: false,
            latency_ms: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize)]
struct LoadTestMetrics {
    url: String,
    method: String,
    duration_secs: u64,
    elapsed_secs: f64,
    target_requests_per_minute: u64,
    concurrency: usize,
    planned_requests: u64,
    completed_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    achieved_requests_per_minute: f64,
    status_counts: BTreeMap<String, u64>,
    error_samples: Vec<String>,
    latency_ms: LatencyMetrics,
}

impl LoadTestMetrics {
    fn from_outcomes(
        url: String,
        method: String,
        duration_secs: u64,
        target_requests_per_minute: u64,
        concurrency: usize,
        planned_requests: u64,
        elapsed: Duration,
        outcomes: Vec<RequestOutcome>,
    ) -> Self {
        let mut status_counts = BTreeMap::new();
        let mut error_samples = Vec::new();
        let mut latencies = Vec::new();
        let mut successful_requests = 0;

        for outcome in &outcomes {
            if outcome.success {
                successful_requests += 1;
            }
            if let Some(status) = outcome.status {
                *status_counts.entry(status.to_string()).or_insert(0) += 1;
            }
            if let Some(latency) = outcome.latency_ms {
                latencies.push(latency);
            }
            if let Some(error) = &outcome.error {
                if error_samples.len() < 5 && !error_samples.contains(error) {
                    error_samples.push(error.to_owned());
                }
            }
        }

        let completed_requests = outcomes.len() as u64;
        let elapsed_secs = elapsed.as_secs_f64().max(0.001);

        Self {
            url,
            method,
            duration_secs,
            elapsed_secs,
            target_requests_per_minute,
            concurrency,
            planned_requests,
            completed_requests,
            successful_requests,
            failed_requests: completed_requests.saturating_sub(successful_requests),
            achieved_requests_per_minute: completed_requests as f64 / elapsed_secs * 60.0,
            status_counts,
            error_samples,
            latency_ms: LatencyMetrics::from_latencies(latencies),
        }
    }

    fn summary(&self) -> String {
        format!(
            "HTTP load test completed: {}/{} successful, {:.1} rpm achieved, p95={} ms, p99={} ms.",
            self.successful_requests,
            self.completed_requests,
            self.achieved_requests_per_minute,
            self.latency_ms.p95.unwrap_or(0),
            self.latency_ms.p99.unwrap_or(0)
        )
    }
}

#[derive(Debug, Default, Serialize)]
struct LatencyMetrics {
    min: Option<u64>,
    avg: Option<f64>,
    p50: Option<u64>,
    p95: Option<u64>,
    p99: Option<u64>,
    max: Option<u64>,
}

impl LatencyMetrics {
    fn from_latencies(mut latencies: Vec<u64>) -> Self {
        if latencies.is_empty() {
            return Self::default();
        }

        latencies.sort_unstable();
        let sum: u64 = latencies.iter().sum();
        let count = latencies.len();

        Self {
            min: latencies.first().copied(),
            avg: Some(sum as f64 / count as f64),
            p50: percentile(&latencies, 0.50),
            p95: percentile(&latencies, 0.95),
            p99: percentile(&latencies, 0.99),
            max: latencies.last().copied(),
        }
    }
}

fn percentile(sorted: &[u64], percentile: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }

    let index = ((sorted.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    sorted.get(index.min(sorted.len() - 1)).copied()
}

fn bounded(tool: &str, field: &str, value: u64, min: u64, max: u64) -> Result<u64> {
    if value < min || value > max {
        return Err(invalid(
            tool,
            format!("{field} must be between {min} and {max}"),
        ));
    }
    Ok(value)
}

fn bounded_usize(tool: &str, field: &str, value: usize, min: usize, max: usize) -> Result<usize> {
    if value < min || value > max {
        return Err(invalid(
            tool,
            format!("{field} must be between {min} and {max}"),
        ));
    }
    Ok(value)
}

fn invalid(tool: &str, message: impl Into<String>) -> ToolError {
    ToolError::InvalidInput {
        tool: tool.to_owned(),
        message: message.into(),
    }
}

fn default_method() -> String {
    "GET".to_owned()
}

fn default_duration_secs() -> u64 {
    DEFAULT_DURATION_SECS
}

fn default_requests_per_minute() -> u64 {
    DEFAULT_REQUESTS_PER_MINUTE
}

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tools::{ToolCall, ToolRegistry};

    #[test]
    fn rejects_non_http_urls() {
        let input = LoadTestInput {
            url: "file:///tmp/example".to_owned(),
            method: default_method(),
            headers: HashMap::new(),
            body: None,
            duration_secs: 1,
            requests_per_minute: 1,
            concurrency: 1,
            timeout_ms: 100,
            success_statuses: None,
        };

        assert!(matches!(
            input.into_plan("http_load_test"),
            Err(ToolError::InvalidInput { .. })
        ));
    }

    #[test]
    fn computes_latency_percentiles() {
        let metrics = LatencyMetrics::from_latencies(vec![10, 30, 20, 40]);

        assert_eq!(metrics.min, Some(10));
        assert_eq!(metrics.p50, Some(20));
        assert_eq!(metrics.p95, Some(40));
        assert_eq!(metrics.p99, Some(40));
        assert_eq!(metrics.max, Some(40));
    }

    #[tokio::test]
    async fn registry_includes_http_load_test() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("http_load_test"));
        assert!(registry.spec("http_load_test").is_some());

        let result = registry
            .dispatch(ToolCall::new(
                "http_load_test",
                json!({
                    "url": "ftp://example.com",
                    "duration_secs": 1,
                    "requests_per_minute": 1,
                    "concurrency": 1,
                    "timeout_ms": 100
                }),
            ))
            .await;
        assert!(matches!(result, Err(ToolError::InvalidInput { .. })));
    }
}
