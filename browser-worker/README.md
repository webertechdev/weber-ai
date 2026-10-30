# Weber AI self-hosted browser worker

This is the provider contract used by the FastAPI backend when `BROWSER_WORKER_URL` is configured. It is an alternative to Browserbase and avoids managed browser-minute quotas, but it is not literally unlimited: the host still needs to stay online, be patched, and have enough CPU, memory, disk, and network capacity.

## Required API contract

The worker must expose the following Browserbase-compatible routes:

- `POST /v1/contexts` with `{ "name": "..." }`, returning `{ "id": "context-id" }`.
- `DELETE /v1/contexts/{context_id}`.
- `POST /v1/sessions` with the Weber browser settings payload, returning `{ "id": "session-id", "connectUrl": "..." }`.
- `GET /v1/sessions/{session_id}/debug`, returning `{ "wsUrl": "...", "debuggerFullscreenUrl": "https://..." }`.
- `POST /v1/sessions/{session_id}` accepting `{ "status": "REQUEST_RELEASE" }`.

Authenticate worker requests with `Authorization: Bearer <BROWSER_WORKER_TOKEN>`. Never expose this token to the browser frontend.

## Recommended deployment

Run Chromium and the worker on an always-on server or persistent VM. Keep Chromium bound to localhost or a private network, put the worker behind HTTPS, require the bearer token, and configure automatic restart with systemd or Docker Compose. Use per-connector isolated browser contexts and delete them on Disconnect. Do not log page contents, cookies, screenshots, or external passwords.

Playwright can attach to Chromium through its CDP endpoint. The official Python API documents `connect_over_cdp`, but the worker should expose only its authenticated HTTPS API rather than a public unauthenticated CDP port:

https://playwright.dev/python/docs/api/class-browsertype#browser-type-connect-over-cdp

## Configuration

Set these Vercel backend variables to enable failover:

```text
BROWSERBASE_API_KEY=existing-managed-key
BROWSER_WORKER_URL=https://your-worker.example.com
BROWSER_WORKER_TOKEN=<random-long-token>
```

If Browserbase returns 402, 429, or a transient 5xx response, Weber retries the same request against the configured worker. If only `BROWSER_WORKER_URL` is configured, the worker becomes the sole browser provider.
