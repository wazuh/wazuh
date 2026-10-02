# API Events Reference

This page documents the Wazuh Engine events ingestion API.

- OpenAPI source: [`spec-events.yaml`](spec-events.yaml); the book also publishes a ReDoc viewer of it beside this page, `api-events-redoc.html`, for the interactive reference

Use this contract to ingest enriched security events into the engine through the
local ingestion socket (`queue/sockets/engine-ingest-http.sock`).
