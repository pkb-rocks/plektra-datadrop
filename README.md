# Plektra datadrop

Receives opt-in typing-training sessions from the Plektra app.

Sessions are gzip-compressed and encrypted on the device with the
[age](https://age-encryption.org/v1) format for the maintainer's X25519 recipient. The
server stores ciphertext only and cannot read session contents. Client IP addresses are
used in memory for rate limiting and are not stored.

## API

- `PUT /v1/sessions/{id}`: body is age ciphertext; `id` is the lowercase hex SHA-256
  prefix (32–64 characters) of the plaintext session. Returns `201` when stored and
  `200` when the session already exists. Optional header `X-Plektra-Version`.
- `POST /v1/sessions/known`: body `{"ids": [...]}`; returns `{"known": [...]}` for
  sessions already stored, so clients can skip them.
- `GET /healthz`

## Run

```sh
go test ./...
go build -o plektra-datadrop .
./plektra-datadrop -listen 127.0.0.1:8080 -data ./data
```

Deployment templates for systemd and Caddy (automatic TLS) are in `deploy/`.

## Decrypt

Requires `rsync` on the server and `age` locally.

The private key stays on the maintainer's machine
(`~/.config/plektra-typing-training/identity.txt` by default).

```sh
tools/pull-and-decrypt.sh <ssh-host> /var/lib/plektra-datadrop ./pulled
```

## License

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`), see `LICENSE`.
