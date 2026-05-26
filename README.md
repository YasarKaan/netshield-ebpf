# NetShield-eBPF

NetShield-eBPF is a host-level network defense agent that uses XDP/eBPF to detect and block abusive traffic, expose Prometheus metrics, and stream live events to a web dashboard.

## Status

> **Pre-production — looking for testers**

The Go backend, REST API, WebSocket layer, React dashboard, Helm chart, and CI pipeline are complete and unit-tested (≈ 50% coverage, all packages passing with `-race`).

**BPF integration tests (CI-verified on Linux):**

`internal/loader/xdp_test.go` contains eight XDP integration tests that run in CI on Ubuntu with `sudo`. They:

- Load the compiled BPF objects into the kernel — **the BPF verifier runs here**. If the verifier rejects the program the test fails immediately.
- Send synthetic Ethernet/IPv4 and Ethernet/IPv6 frames through the XDP program using `BPF_PROG_RUN` and assert `XDP_PASS` or `XDP_DROP` as expected.
- Cover the blocklist path for both IPv4 (`blocklist_map`) and IPv6 (`blocklist_v6_map`).

These tests run with `go test -run TestXDP ./internal/loader/...` on any Linux machine with kernel ≥ 5.10 and `CAP_BPF` / root.

**What is still unvalidated:**

- **Physical NIC attachment** — `link.AttachXDP` against a real or virtual network interface has not been tested. The XDP program runs correctly in the kernel (as proven by the integration tests above), but `XDP_GENERIC` / `XDP_NATIVE` attachment to a specific interface is untested.
- **Real traffic** — end-to-end blocking of live packets on a host has not been observed.

**In practice:**

The BPF verifier and program logic are CI-tested. The remaining unknown is interface attachment. If you run `go run ./cmd/netshield` on Linux and the XDP attach step fails, please open an issue with your kernel version and the error message.

## What It Includes

- Go agent with XDP/eBPF loader, packet analysis, blocklist management, and REST/WebSocket APIs
- React dashboard for live traffic, events, and blocklist operations
- Prometheus metrics endpoint on `:2112`
- Docker Compose stack with Prometheus and Grafana
- Helm chart for Kubernetes deployment as a DaemonSet

## Local Development

### Backend

```bash
go test ./...
go run ./cmd/netshield --config config.example.yaml --mock=true
```

The agent listens on:

- API: `http://localhost:8080`
- Metrics: `http://localhost:2112/metrics`

### Frontend

```bash
cd web
npm ci
npm run dev
```

The dashboard expects the agent on port `8080` and connects over WebSocket automatically.

## Docker Compose

```bash
docker compose up --build
```

Services:

- Agent API: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`
- Web UI: `http://localhost:3000`

## Configuration

Start from `config.example.yaml`.

Important settings:

- `interface`: network interface for XDP attachment
- `analyzer.rate_limit` and `analyzer.port_scan`: detection thresholds
- `api.auth.token`: bearer token for protected API calls
- `notifier`: Slack and Discord webhook settings

Environment variable expansion is supported in config values, so you can use `${AUTH_TOKEN}` in YAML.

## Kubernetes / Helm

Package or install the chart from `helm/netshield`. The chart deploys:

- Agent as a Linux-only DaemonSet
- Web dashboard as a Deployment
- Agent auth token through a Kubernetes Secret

Example:

```bash
helm install netshield ./helm/netshield
```

## Security Notes

- Change the default API token before exposing the API anywhere outside local development.
- Grafana anonymous admin access is disabled by default in Compose.
- GeoIP databases and local `config.yaml` should not be committed.

## Project Layout

- `cmd/netshield`: agent entrypoint
- `internal/analyzer`: rate limit and port-scan detection
- `internal/api`: REST and WebSocket server
- `internal/blocker`: blocklist application and lifecycle
- `web`: dashboard
- `helm/netshield`: Kubernetes manifests
- `deploy`: Prometheus and Grafana assets
