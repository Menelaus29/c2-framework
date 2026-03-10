# Network Configuration

## Lab Environment Overview

Two VirtualBox VMs on a host-only network, plus the host Windows machine.

| Host | IP | Role |
|---|---|---|
| Windows Host (dev machine) | 192.168.100.1 | Development, git push/pull |
| Ubuntu VM (c2-server) | 192.168.100.10 | C2 server, Nginx redirector |
| Windows VM (c2-victim) | 192.168.100.20 | Agent victim machine |

---

## VirtualBox Network Adapters

### Ubuntu VM
| Adapter | Type | Interface | IP | Purpose |
|---|---|---|---|---|
| Adapter 1 | NAT | enp0s3 | 10.0.2.15 (DHCP) | Internet access, git pull |
| Adapter 2 | Host-only | enp0s8 | 192.168.100.10/24 (static) | C2 traffic |

### Windows VM
| Adapter | Type | IP | Purpose |
|---|---|---|---|
| Adapter 1 | NAT | DHCP | Internet access |
| Adapter 2 | Host-only | 192.168.100.20/24 (static) | C2 traffic |

---

## DNS Resolution

The agent resolves `c2.lab.internal` via the Windows VM hosts file:
```
C:\Windows\System32\drivers\etc\hosts
192.168.100.10    c2.lab.internal
```

---

## Port Layout

### Bare-Metal Deployment
```
Windows VM (192.168.100.20)
        |
        | HTTPS :8443
        v
Ubuntu VM (192.168.100.10)
        |
        | uvicorn binds 0.0.0.0:8443 (TLS)
        v
server/server_main.py
        |
        | aiosqlite
        v
logs/c2_server.db
```

### Docker Compose Deployment
```
Windows VM (192.168.100.20)
        |
        | HTTPS :443
        v
Ubuntu VM (192.168.100.10)
        |
        | Docker host port 443
        v
c2-nginx container (nginx:stable-alpine + headers-more)
        |
        | HTTP :8443 (Docker internal network: c2-internal)
        v
c2-server container (python:3.11-slim)
        |
        | aiosqlite
        v
logs/c2_server.db (bind mount → host ~/c2-framework/logs/)
```

---

## Service Responsibilities

| Component | Port | Protocol | Responsibility |
|---|---|---|---|
| c2-nginx | 443 (host) | HTTPS | TLS termination, UA filter, routing |
| c2-nginx | 80 (host) | HTTP | Redirect to HTTPS |
| c2-server | 8443 (internal) | HTTP | Beacon handler, session/task management |

---

## Key Behaviours

- Agent always connects to port 443 in Docker deployment — never directly to 8443
- Port 8443 is not exposed to the host network — only reachable within the `c2-internal` Docker bridge
- Nginx validates UA and Content-Type before proxying — invalid requests never reach the backend
- TLS cert is mounted into both containers from the host `certs/` directory
- DB and logs persist outside containers via bind mounts to `logs/`
- `BEHIND_NGINX=1` is set via Docker Compose environment — no manual config edit required

---

## Static IP Configuration (Ubuntu VM)

Configured via `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg` and netplan.

`/etc/netplan/50-cloud-init.yaml`:
```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      addresses:
        - 192.168.100.10/24
```

Apply with:
```bash
sudo netplan apply
```

---

## TLS Certificate

Self-signed cert with SAN extension covering both hostname and IP:
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -days 365 -nodes \
  -subj "/CN=c2.lab.internal" \
  -addext "subjectAltName=DNS:c2.lab.internal,IP:192.168.100.10"
```

- `certs/server.crt` — committed to repo, copied to Windows VM
- `certs/server.key` — gitignored, never leaves Ubuntu VM
- Agent pins the cert via `transport/tls_wrapper.py`