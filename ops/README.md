# Ops artifacts

Ready-to-drop Prometheus + Grafana configs for the catalog API.

## `prometheus/alerts.yml`

Prometheus alerting rules grouped by concern (HTTP, auth, storage).
Copy to your Prometheus server's rule-files directory and reload.

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/nks-wdc-catalog-alerts.yml
```

Rules cover:

- **HTTP**: 5xx ratio > 2 % · p99 latency > 2 s · zero admin traffic
  during business hours
- **Auth**: overall failure rate > 10/min · sustained RBAC denials
- **Storage**: blob-orphan growth (MinIO/S3 delete failures) · retention
  runner stalled for > 26 h

Tune thresholds to your traffic profile — the defaults assume a
single-tenant admin panel with light load (< 5 req/s baseline).

## `grafana/dashboard.json`

A single dashboard with four KPI stats on top (req/s, 5xx ratio, p99
latency, auth failures/min) plus four time-series + a top-routes table.

Import via Grafana:

1. **Dashboards → New → Import**
2. Paste the JSON contents
3. Select your Prometheus datasource

The datasource field uses the literal string `"Prometheus"` — rename in
the JSON if your stack labels the datasource differently.

## Metrics exposed

All metrics live on `/metrics` (Prometheus text format). Names:

| Metric | Labels | Meaning |
|---|---|---|
| `nks_wdc_http_requests_total` | `method,status,route` | HTTP request counter |
| `nks_wdc_http_request_duration_seconds` | `method,route` | Request latency histogram |
| `nks_wdc_snapshot_created_total` | `kind` | Snapshots committed |
| `nks_wdc_retention_deleted_total` | — | Retention deletions |
| `nks_wdc_blob_orphan_total` | — | Blob deletes that failed at object store |
| `nks_wdc_auth_failures_total` | `reason` | Auth/authz failures bucketed by cause |
