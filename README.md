# gcp-log-csp

> **Note:** This project was mostly coded by [GitHub Copilot](https://github.com/features/copilot).

A minimal [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) report collector that logs violations as [Google Cloud Platform structured logs](https://cloud.google.com/logging/docs/structured-logging). Designed to run on [Cloud Run](https://cloud.google.com/run).

## Design Goals

- **Minimal attack surface** — written in Rust and deployed in a `scratch` Docker container with no OS, shell, or extra libraries.
- **Performant** — async I/O with `axum` / `tokio`.
- **Simple** — one binary, zero configuration beyond an optional `PORT` environment variable.

## Endpoints

| Method | Path              | Description                              |
|--------|-------------------|------------------------------------------|
| POST   | `$CSP_ENDPOINT`   | Accepts CSP violation reports            |
| GET    | `/health`         | Health check (returns `200 OK`)          |

### Accepted Content Types

The CSP report endpoint accepts these content types:

- `application/csp-report` — legacy `report-uri` directive format
- `application/reports+json` — Reporting API v1 format
- `application/json` — generic JSON

## Configuration

| Variable       | Default        | Description                        |
|----------------|----------------|------------------------------------|
| `PORT`         | `8080`         | Port to listen on                  |
| `CSP_ENDPOINT` | `/csp-report`  | Path for the CSP report endpoint   |

## Usage

### Run Locally

```bash
cargo run
```

### Docker

```bash
docker build -t gcp-log-csp .
docker run -p 8080:8080 gcp-log-csp
```

### Deploy to Cloud Run

```bash
# Build and push to Google Artifact Registry
docker build -t us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest .
docker push us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest

# Deploy
gcloud run deploy gcp-log-csp \
  --image us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest \
  --allow-unauthenticated
```

### CSP Header Example

Point your CSP reporting to the deployed service:

```
Content-Security-Policy: default-src 'self'; report-uri https://YOUR-SERVICE-URL/csp-report
```

Or with the newer Reporting API:

```
Content-Security-Policy: default-src 'self'; report-to csp-endpoint
Reporting-Endpoints: csp-endpoint="https://YOUR-SERVICE-URL/csp-report"
```

## Alerting

The `sample_alerts/` directory contains sample GCP Cloud Monitoring configurations
that work with the structured logs produced by this service.

### Log structure

Every valid CSP report is logged as a JSON structured log entry:

```json
{
  "severity": "WARNING",
  "message": "CSP violation report received",
  "csp-report": { /* the raw browser report */ }
}
```

For the legacy `report-uri` format the report body looks like:

```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src 'self'",
    "blocked-uri": "https://evil.com/script.js",
    "original-policy": "script-src 'self'; report-uri /csp-report"
  }
}
```

So the full JSON path to the referring page URL in Cloud Logging is:

```
jsonPayload["csp-report"]["csp-report"]["document-uri"]
```

### Alert: more than N reports from a referring domain

`sample_alerts/log-metric-csp-by-referrer.yaml` defines a **log-based metric** that
counts CSP reports and labels each data point with the hostname extracted from
`document-uri` (e.g. `"example.com"`).

`sample_alerts/alert-policy-csp-by-referrer.yaml` defines an **alert policy** that
fires when any single referring domain generates more than **100 reports within
a 5-minute window**. Adjust `thresholdValue` to match your expected traffic
before deploying.

#### Deploying

```bash
# 1. Create the log-based metric (once per project)
gcloud logging metrics create csp_reports_by_referrer \
  --config-from-file=sample_alerts/log-metric-csp-by-referrer.yaml

# 2. Create the alert policy
gcloud alpha monitoring policies create \
  --policy-from-file=sample_alerts/alert-policy-csp-by-referrer.yaml
```

To attach a notification channel (email, Slack, PagerDuty, etc.) first look
up its resource name and then add it to the `notificationChannels` list in
`alert-policy-csp-by-referrer.yaml`:

```bash
gcloud alpha monitoring channels list
```

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo test

# Build release
cargo build --release
```

## License

[MIT](LICENSE)
