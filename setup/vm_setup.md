## TLS Certificate Generation

Run the following on the Ubuntu server VM to generate the self-signed certificate:

    openssl req -x509 -newkey rsa:4096 \
      -keyout certs/server.key \
      -out certs/server.crt \
      -days 365 -nodes \
      -subj "/CN=c2.lab.internal"

Breakdown:
* req -x509        generate a self-signed certificate (not a CSR)
* -newkey rsa:4096 generate a new 4096-bit RSA private key alongside it
* -keyout          where to write the private key
* -out             where to write the certificate
* -days 365        certificate is valid for 1 year
* -nodes           do not encrypt the private key with a passphrase
                 (needed so the server can start without manual input)
* -subj            set the CN (Common Name) to c2.lab.internal
                 skips the interactive prompts

### Certificate locations
| File        | Location (Ubuntu VM)                        | Location (Windows VM)                        |
|-------------|---------------------------------------------|----------------------------------------------|
| server.crt  | ~/c2-framework/certs/server.crt  | C:\Users\<username>\certs\server.crt         |
| server.key  | ~/c2-framework/certs/server.key  | NEVER copied to Windows VM                  |

### Important rules
- server.key must NEVER leave the Ubuntu VM
- server.key must NEVER be committed to Git
- server.crt is safe to copy — it is a public certificate
- Both files are excluded from Git via .gitignore
