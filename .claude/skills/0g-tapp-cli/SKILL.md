---
name: 0g-tapp-cli
description: Use this skill when the user wants to deploy, manage, or troubleshoot applications on a 0G Tapp (Trusted Application Platform) server using tapp-cli. Covers start/stop apps, check task status, view logs, and manage docker compose deployments on remote TEE servers.
version: 1.1.0
author: 0G Labs
tags: [0g, tapp, tee, docker, deployment, cli]
---

# 0G Tapp CLI Skill

Deploy and manage containerized applications on 0G Tapp TEE servers using `tapp-cli`.

## Environment

- **tapp-cli binary**: `/usr/local/bin/tapp-cli`
- **Server**: specified via `-s <url>` flag (e.g. `http://<host>:50051`)
- **Auth**: Private key via `-k` flag or `TAPP_PRIVATE_KEY` env var

## Core Commands

```bash
# Login to a private Docker registry (run once per registry per server)
tapp-cli -s <server> docker-login -r <registry-host> -u <user> -p <password>

# Start app (auto-uploads local volume files)
tapp-cli -s <server> start-app -f docker-compose.yaml --app-id <id>

# Check async task result (start-app / stop-app are async, return a task-id)
tapp-cli -s <server> get-task-status --task-id <task-id>

# Stop app (all containers)
tapp-cli -s <server> stop-app --app-id <id>

# Stop / start a single service within a running app
# NOTE: flag is --service-name (NOT --service)
tapp-cli -s <server> stop-service --app-id <id> --service-name <svc>
tapp-cli -s <server> start-service --app-id <id> --service-name <svc>

# Container status
tapp-cli -s <server> get-app-container-status --app-id <id>

# App logs (all services or specific service)
tapp-cli -s <server> get-app-logs --app-id <id> -n 100
tapp-cli -s <server> get-app-logs --app-id <id> --service <name> -n 50

# Retrieve the TEE-derived app signing key (Ethereum address)
tapp-cli -s <server> get-app-key --app-id <id>
```

## Deploying docker-compose Apps — Key Rules

### What tapp-cli uploads automatically
Scans `volumes:` in docker-compose.yaml and uploads files/directories whose source path starts with `./`:
- `./config/app.conf` → uploaded ✓
- `./certs/server.crt` → uploaded ✓
- `./certs/` (directory) → uploaded recursively ✓
- `../other/config.yaml` → **error, not supported** ✗

### Common pitfalls and fixes

**1. `../` relative paths are not supported**
- Each app runs isolated under its own server directory (`/var/lib/tapp/apps/<app_id>/`)
- A `../` source path would resolve outside that boundary, which the server rejects for security
- tapp-cli will print an error and skip such paths
- **Fix**: copy the file into the compose directory and use a `./` path
```yaml
# Bad — tapp-cli will print an error and skip this
- ../other/otel-config.yaml:/etc/otelcol/config.yaml

# Good — copy file to compose dir
- ./otel-config.yaml:/etc/otelcol/config.yaml
```

**2. `.env` is not uploaded (not referenced in volumes)**
- Docker Compose reads `.env` from working dir for `${VAR}` substitution
- Fix: mount `./.env` in any service to force tapp-cli to upload it
```yaml
some-service:
  volumes:
    - ./.env:/etc/app/.env:ro   # tapp-cli uploads it; docker compose finds it in app dir
```

**4. App already running — must stop before re-deploy**
```bash
tapp-cli -s <server> stop-app --app-id <id>
# then re-deploy
tapp-cli -s <server> start-app -f docker-compose.yaml --app-id <id>
```

## Troubleshooting Workflow

1. Check task result after `start-app`:
   ```bash
   tapp-cli -s <server> get-task-status --task-id <task-id>
   ```
2. Check container states:
   ```bash
   tapp-cli -s <server> get-app-container-status --app-id <id>
   ```
3. Check logs of the failing container:
   ```bash
   tapp-cli -s <server> get-app-logs --app-id <id> --service <name> -n 50
   ```
4. Common root causes:
   - `restarting` container → check logs for missing env vars or missing mount files
   - Missing config/cert → mount file was skipped (check for `../` paths in compose file)
   - New image version with new required env vars → update compose file and re-deploy
