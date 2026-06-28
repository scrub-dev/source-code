# Deploy on Kubernetes

SCRUB ships a Helm chart published as an **OCI artifact** on every release. It runs
the hardened container image (non-root, read-only rootfs), serves a `ClusterIP` on
`:8080` with `/healthz` probes, and scales from a single pod to a Redis-backed HA
cluster.

## Install

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z
```

This deploys one replica with the default config (a dry-run reverse proxy to OpenAI).
Point your app at the in-cluster Service:

```
http://scrub.<namespace>.svc:8080/openai/v1/chat/completions
```

## Configure

Put your SCRUB config under `config:` in a values file — its contents become the
mounted `scrub.yaml`:

```yaml
# my-values.yaml
config:
  routes:
    - { listen_path: /openai, upstream: https://api.openai.com, profile: openai }
  profiles:
    openai:
      scan_paths: ["messages[].content"]
      stream_paths: ["choices[].delta.content"]
  masking:
    mode: enforce
  rules:
    - { name: email, type: EMAIL, pattern: '[\w.+-]+@[\w.-]+\.\w+', priority: 50 }
```

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z -f my-values.yaml
```

Prefer to manage the config yourself? Set `existingConfigMap` to a ConfigMap that has
a `scrub.yaml` key.

## High availability

For multiple instances sharing **session-scoped** pseudonyms, enable HA. The chart
switches to a **StatefulSet** so each pod gets a stable ordinal, fed to SCRUB as a
distinct `node_id` — the id-space partition that keeps concurrent nodes from
colliding. Pods share state through Redis, encrypted at rest.

```mermaid
flowchart TD
    SVC["Service :8080"] --> P0["scrub-0 · node_id 0"]
    SVC --> P1["scrub-1 · node_id 1"]
    SVC --> P2["scrub-2 · node_id 2"]
    P0 & P1 & P2 --> R[("Redis<br/>encrypted session maps")]
    subgraph SS["StatefulSet (pod ordinal → SCRUB_NODE_ID)"]
      P0
      P1
      P2
    end
```

### Turnkey: bundled Redis

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z \
  --set ha.enabled=true --set replicaCount=3 \
  --set redis.enabled=true --set redis.password=$(openssl rand -hex 16) \
  --set sessions.encryptionKey=$(openssl rand -hex 32) \
  --set config.masking.scope=session
```

This deploys a single dependency-free Redis (official image) alongside SCRUB — fine
for many setups. For durability, add `--set redis.persistence.enabled=true`.

### Production: external/managed Redis

Point at your own Redis (managed service, or a clustered/HA Redis) and leave the
bundled one off:

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z \
  --set ha.enabled=true --set replicaCount=3 \
  --set redis.url=rediss://scrub:pass@redis.internal:6379/0 \
  --set sessions.encryptionKey=$(openssl rand -hex 32) \
  --set config.masking.scope=session
```

HA also adds a **PodDisruptionBudget** and soft **anti-affinity**; set
`autoscaling.enabled=true` for an HPA. The credentials (Redis URL + at-rest key) are
held in a Secret and injected via `secretKeyRef`, never as plain pod env.

> Requires Kubernetes **≥ 1.28** (the `apps.kubernetes.io/pod-index` downward-API
> label). The Redis URL/key can also live in your own Secret — set
> `sessions.existingSecret` to a Secret with keys `redis-url` and `encryption-key`.

## Verify

```sh
helm test scrub            # hits /healthz from an in-cluster pod
kubectl get pods -l app.kubernetes.io/name=scrub
```

## Without Helm

The same cluster wiring works via environment variables on any orchestrator —
`SCRUB_NODE_ID`, `SCRUB_REDIS_URL`, `SCRUB_ENCRYPTION_KEY`, `SCRUB_SESSION_BACKEND`
override the config's `sessions` block. See the
[configuration reference](../docs/configuration.html#cli--environment).
