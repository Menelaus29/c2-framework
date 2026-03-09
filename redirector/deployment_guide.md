# Nginx Redirector — Deployment Guide

## Overview

Nginx sits on port 443 and terminates TLS. It forwards only POST /beacon
requests to the C2 server running on port 8443 (plain HTTP, loopback only).
All other paths return a fake normal website.

---

## Prerequisites

- Ubuntu VM with Nginx installed
- TLS cert and key at /home/c2server/c2-framework/certs/server.{crt,key}
- C2 server running on 127.0.0.1:8443

---

## Step 1 — Install Nginx
```bash
sudo apt update
sudo apt install nginx -y
```

---

## Step 2 — Allow HTTPS through firewall
```bash
sudo ufw allow 443/tcp
```

Check:
```bash
sudo ufw status
```

Expected output:
```
443/tcp                    ALLOW       Anywhere
```

---

## Step 3 — Copy the config
```bash
sudo cp ~/c2-framework/redirector/nginx_example.conf \
        /etc/nginx/sites-available/c2
```

---

## Step 4 — Enable the site
```bash
sudo ln -s /etc/nginx/sites-available/c2 /etc/nginx/sites-enabled/c2
sudo rm -f /etc/nginx/sites-enabled/default
```

---

## Step 5 — Test the config
```bash
sudo nginx -t
```

Expected output:
```
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

---

## Step 6 — Set cert permissions

Nginx runs as www-data and must read the cert and key:
```bash
sudo chmod 640 /home/c2server/c2-framework/certs/server.key
sudo chown root:www-data /home/c2server/c2-framework/certs/server.key
sudo chmod 644 /home/c2server/c2-framework/certs/server.crt
```

---

## Step 7 — Set BEHIND_NGINX in common/config.py
```python
BEHIND_NGINX = True
```

This tells the server to start without TLS since Nginx handles termination.

---

## Step 8 — Start the C2 server (no TLS) (must start before Nginx)
Inside the project directory, run:
```bash
source source .venv/bin/activate 
python -m server.server_main
```

Confirm its logs:
```
{"message": "server started", "port": 8443}
```

---

## Step 9 — Start Nginx
```bash
sudo systemctl restart nginx
sudo systemctl enable nginx
```

---

## Step 10 — Verify the proxy

From the Ubuntu VM, test that /beacon accepts POST:
```bash
curl -k --resolve c2.lab.internal:443:127.0.0.1 \
     -X POST https://c2.lab.internal/beacon \
     -H 'Content-Type: application/octet-stream' \
     -d 'test'
```

Expected: `400` (bad protocol — proves Nginx forwarded to backend correctly, but server rejected the payload because it's not a valid encrypted protocol message).

Test that other paths return 404:
```bash
curl -k https://127.0.0.1/ -o /dev/null -w '%{http_code}\n'
curl -k https://127.0.0.1/admin -o /dev/null -w '%{http_code}\n'
```

Expected: `404` for both.

---

## Step 11 — Verify Server header spoofing
```bash
curl -k -I https://127.0.0.1/
```

Expected header:
```
Server: Apache/2.4.54
```

---

## Step 12 — Check access logs
```bash
sudo tail -f /var/log/nginx/c2_access.log
```

Start the agent on the Windows VM and confirm beacon requests appear in the log.

---

## Troubleshooting

**502 Bad Gateway** — C2 server is not running on 8443. Start it first.

**Permission denied on cert key** — re-run Step 5.

**nginx -t fails** — check cert paths in nginx_example.conf match actual paths on disk.