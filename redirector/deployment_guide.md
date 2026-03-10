# Redirector Deployment Guide

Two deployment methods are supported: **bare-metal** (Nginx installed directly on
the Ubuntu VM) and **Docker Compose** (recommended for clean reproducibility).

---

## Prerequisites (both methods)

- Ubuntu VM with the repo cloned at `/home/c2server/c2-framework`
- TLS cert and key at `/home/c2server/c2-framework/certs/server.{crt,key}`
- `common/config.py` exists (copy from `common/config_example.py` if not present)
- Python venv initialised at `/home/c2server/c2-framework/.venv`

---

# Method 1 — Bare-Metal (Nginx on host)

---

## Step 1 — Install Nginx
```bash
sudo apt update
sudo apt install nginx -y
```

---

## Step 2 — Copy fake website to web root
```bash
sudo mkdir -p /var/www/html
sudo cp /home/c2server/c2-framework/redirector/site/* /var/www/html/
```

---

## Step 3 — Copy Nginx config
```bash
sudo cp /home/c2server/c2-framework/redirector/nginx_example.conf \
        /etc/nginx/sites-available/c2
```

---

## Step 4 — Enable the site and disable the default
```bash
sudo ln -s /etc/nginx/sites-available/c2 /etc/nginx/sites-enabled/c2
sudo rm -f /etc/nginx/sites-enabled/default
```

---

## Step 5 — Set cert permissions

Nginx runs as `www-data` and must be able to read the cert and key:
```bash
sudo chmod 644 /home/c2server/c2-framework/certs/server.crt
sudo chmod 640 /home/c2server/c2-framework/certs/server.key
sudo chown root:www-data /home/c2server/c2-framework/certs/server.key
```

---

## Step 6 — Test the Nginx config
```bash
sudo nginx -t
```

Expected output:
```
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

If this fails, check that the cert paths in `nginx_example.conf` match the
actual paths on disk.

---

## Step 7 — Set BEHIND_NGINX in common/config.py

Open `common/config.py` and ensure this line is present:
```python
BEHIND_NGINX = os.environ.get('BEHIND_NGINX', '0') == '1'
```

For bare-metal, export the variable before starting the server:
```bash
export BEHIND_NGINX=1
```

---

## Step 8 — Start the C2 server (must start before Nginx)
```bash
cd /home/c2server/c2-framework
source .venv/bin/activate
python -m server.server_main
```

Confirm it logs:
```json
{"message": "server started", "port": 8443}
```

The server must be running before Nginx starts — otherwise Nginx returns
`502 Bad Gateway` on the first request.

---

## Step 9 — Start Nginx
```bash
sudo systemctl restart nginx
sudo systemctl enable nginx
```

---

## Step 10 — Open firewall port if UFW is enabled
```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
```

---

## Step 11 — Verify /beacon returns 400

A `400` response confirms Nginx forwarded the request to the backend and the
backend rejected it as an invalid protocol message — both services are working
correctly.
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     -X POST https://c2.lab.internal/beacon \
     -H 'Content-Type: application/octet-stream' \
     -d 'test' -o /dev/null -w '%{http_code}\n'
```

Expected: `400`

---

## Step 12 — Verify other paths return 404 or serve fake site
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     https://c2.lab.internal/ -o /dev/null -w '%{http_code}\n'
```

Expected: `200` (fake website served)
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     https://c2.lab.internal/admin -o /dev/null -w '%{http_code}\n'
```

Expected: `404`

---

## Step 13 — Verify Server header spoofing
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     -I https://c2.lab.internal/
```

Expected header:
```
Server: Apache/2.4.54
```

---

## Step 14 — Check access logs

Log files are created automatically after the first request.
```bash
sudo tail -f /var/log/nginx/c2_access.log
```

Start the agent on the Windows VM and confirm beacon requests appear.

---

---

# Method 2 — Docker Compose (recommended)

No manual config edits required. `BEHIND_NGINX` is set automatically via the
compose environment block.

---

## Step D1 — Install Docker and Docker Compose
```bash
sudo apt update
sudo apt install docker.io docker-compose-plugin -y
sudo usermod -aG docker c2server
newgrp docker
```

---

## Step D2 — Verify cert and log directory permissions

The container runs as UID 1000. Confirm your user UID matches:
```bash
id c2server
```

Expected: `uid=1000`

Set correct permissions on mounted paths:
```bash
chmod 644 /home/c2server/c2-framework/certs/server.crt
chmod 640 /home/c2server/c2-framework/certs/server.key
chmod 755 /home/c2server/c2-framework/logs/
chmod 644 /home/c2server/c2-framework/common/config.py
```

---

## Step D3 — Verify common/config.py reads BEHIND_NGINX from environment

Open `common/config.py` and confirm this line is present:
```python
BEHIND_NGINX = os.environ.get('BEHIND_NGINX', '0') == '1'
```

No other edits to `config.py` are needed — Docker Compose sets `BEHIND_NGINX=1`
automatically via the environment block in `docker-compose.yml`.

---

## Step D4 — Update nginx_example.conf for Docker cert paths

The Docker nginx container mounts certs at `/etc/nginx/certs/`. Confirm these
lines are set in `redirector/nginx_example.conf`:
```nginx
ssl_certificate     /etc/nginx/certs/server.crt;
ssl_certificate_key /etc/nginx/certs/server.key;
```

And confirm `proxy_pass` uses the Docker service name:
```nginx
proxy_pass http://c2-server:8443/beacon;
```

---

## Step D5 — Start both services

Run from project root: 
```bash
cd /home/c2server/c2-framework
docker compose up -d
```

Expected output:
```
[+] Running 2/2
 ✔ Container c2-server  Started
 ✔ Container c2-nginx   Started
```

---

## Step D6 — Verify /beacon returns 400
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     -X POST https://c2.lab.internal/beacon \
     -H 'Content-Type: application/octet-stream' \
     -d 'test' -o /dev/null -w '%{http_code}\n'
```

Expected: `400`

A `502` means the c2-server container is not running — check Step D7.
A `404` means Nginx is running but the location block did not match — check
the `proxy_pass` hostname in `nginx_example.conf`.

---

## Step D7 — View logs

View nginx access log:
```bash
docker compose logs nginx
```

View c2-server log:
```bash
docker compose logs c2-server
```

Follow live:
```bash
docker compose logs -f
```

Log files are created automatically after the first request.

---

## Step D8 — Stop both services
```bash
docker compose down
```

To also remove the internal network:
```bash
docker compose down --remove-orphans
```

---

---

# Troubleshooting (both methods)

| Symptom | Cause | Fix |
|---|---|---|
| `502 Bad Gateway` | c2-server not running | Start server before Nginx; check server logs |
| `404` on `/beacon` | location block mismatch | Check `proxy_pass` and `location = /beacon` in conf |
| `Permission denied` on cert key | Wrong file ownership | Re-run cert permission steps |
| `nginx -t` fails | Bad cert path in conf | Verify absolute paths match actual file locations |
| No log file yet | No requests received | Log files created on first request |
| Agent cannot connect | Firewall blocking 443 | Run `sudo ufw allow 443/tcp` |
| Docker volume permission error | UID mismatch | Confirm `id c2server` returns `uid=1000` |