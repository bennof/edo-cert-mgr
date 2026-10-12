# edo-cert-mgr

Command line tool for a small private certificate authority (TLS/https and mTLS) and for SSH `known_hosts`.
It replaces the old `ca.sh` script and works on the same directory layout, so existing CAs created with `ca.sh` can be used directly.

## Installation

```sh
npm i -g github:bennof/edo-cert-mgr
```

npm clones the repository, builds it and installs the command `edo-cert-mgr`.

Requirements:

- Node.js (tested with 22)
- `openssl` (the macOS system LibreSSL works)
- for `knownhosts`: `ssh-keygen`, `ssh-keyscan`, `ssh-copy-id` (OpenSSH)

## Usage

```sh
edo-cert-mgr tree                         # certificates in ./pki
edo-cert-mgr -d ~/.ssh/local_cert/pki tree
edo-cert-mgr knownhosts                   # always works in ~/.ssh
```

`-d, --directory <path>` sets the certificate directory (default `./pki`). It is created on the first write.

### tree

Shows the certificate tree and lets you select a node:

```
❯ └── ▾ pki/
        └── ▾ root  root  until 2036-09-03
            ├── ▾ mtls  intermediate  until 2031-09-05
            │   ├──   rowlf  client  until 2028-12-09
            │   └──   code-server-cert  server  until 2028-12-09
            └── ▾ local_https  intermediate  until 2031-09-05
                └──   piggy  server  until 2028-12-09
```

Keys: `↑↓` move, `→` expand, `←` collapse or go to parent, `Enter` opens the menu, `q` quits.

| Selected node | new | update | delete |
|---|---|---|---|
| directory | root CA | – | – |
| root / intermediate CA | intermediate CA, mtls (client) or https (server) certificate | renew this CA and everything below | delete this CA and everything below |
| certificate | – | renew | delete |

`update` keeps the existing keys and signs the existing CSRs again with a fresh validity period.
Because the root key stays the same, a renewed root does not need to be reinstalled on your devices.

Passphrases: CA keys can be encrypted (asked when created, empty = unencrypted). Server and client keys are always unencrypted, so servers can start unattended.

### knownhosts

Menu with `list`, `add`, `remove` for `~/.ssh/known_hosts`.
`add` creates a key `~/.ssh/id_ed25519_<host>`, records the host key, writes a `Host` block to `~/.ssh/config` and copies the public key to the host with `ssh-copy-id`.

## Directory layout

Same as `ca.sh`. CA directories lie side by side; the hierarchy is read from the certificates.

```
pki/
└── <ca>/
    ├── private/ca.key.pem
    ├── certs/ca.cert.pem
    ├── certs/ca.mtls.pem          CA chain for nginx ssl_client_certificate
    ├── ca.cnf  index.txt  serial  csr/  newcerts/
    └── issued/<name>/
        ├── <name>.key.pem
        ├── <name>.cert.pem
        ├── <name>.fullchain.pem   certificate + all CAs up to the root
        ├── <name>.p12             client certificates only
        └── <name>.csr.pem  <name>.ext.cnf   needed for update, keep them
```

## Using the certificates

**https server (nginx)**

```nginx
ssl_certificate     .../issued/<name>/<name>.fullchain.pem;
ssl_certificate_key .../issued/<name>/<name>.key.pem;
```

Install `root/certs/ca.cert.pem` as trusted on the clients (macOS keychain "System" → always trust; Firefox has its own store).

**mTLS server (nginx)**

```nginx
ssl_client_certificate  .../<mtls-ca>/certs/ca.mtls.pem;
ssl_verify_client       on;
ssl_verify_depth        2;
```

**mTLS clients**

- Browsers (macOS, Windows, Linux, iOS): import `<name>.p12`. Firefox needs its own import.
- Command line: `curl --cert <name>.cert.pem --key <name>.key.pem https://…`

The `.p12` uses 3DES/SHA1, because the macOS keychain cannot use keys from AES encrypted `.p12` files.
The protection therefore depends on the export password: use a long random one and delete the `.p12` after importing it.

## Development

```sh
npm install
npm run dev -- tree -d ./pki    # run from source
npm run build                   # compile to dist/
```
