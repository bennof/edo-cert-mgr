#!/usr/bin/env bash
#
# ca.sh — einfacher OpenSSL-Wrapper für eine private CA-Hierarchie
# (Root-CA -> beliebig viele Intermediate-CAs -> Server-/Client-Zertifikate)
#
# Gedacht für privaten Einsatz: TLS (Server-Zertifikate) und mTLS
# (zusätzlich Client-Zertifikate). Alle privaten Schlüssel werden mit
# Passphrase verschlüsselt (AES-256), außer du übergibst -nopass explizit.
#
# Layout:
#   pki/<ca-name>/{private,certs,csr,newcerts}/  + index.txt, serial, ca.cnf
#
# Nutzung:
#   ./ca.sh init-root   <ca-name> [--days N] [--bits N]
#   ./ca.sh init-inter  <ca-name> --parent <parent-ca-name> [--days N] [--bits N]
#   ./ca.sh issue-server <cert-name> --parent <ca-name> --cn <hostname> [--san dns:foo,dns:bar,ip:1.2.3.4] [--days N] [--bits N]
#   ./ca.sh issue-client <cert-name> --parent <ca-name> --cn <username> [--days N] [--bits N]
#   ./ca.sh chain        <cert-name> --parent <ca-name>      # baut Fullchain-Datei
#   ./ca.sh export-p12   <cert-name> --parent <ca-name> [--out <datei.p12>]  # Key+Cert+CA als .p12 bündeln
#   ./ca.sh show         <path-zu-pem>                       # Zertifikat anzeigen
#
# Beispiel eigene CA-Kette (Root -> Intermediate -> Server):
#   ./ca.sh init-root    root
#   ./ca.sh init-inter   inter1 --parent root
#   ./ca.sh issue-server myhost --parent inter1 --cn myhost.local --san "dns:myhost.local,dns:*.myhost.local"
#   ./ca.sh chain        myhost --parent inter1
#
# Für mTLS zusätzlich Client-Zerts ausstellen und die Root-/Intermediate-
# Kette als "ca-bundle" auf dem Server als vertrauenswürdig hinterlegen
# (z. B. bei nginx: ssl_client_certificate / ssl_verify_client).

set -euo pipefail

BASE_DIR="${CA_BASE_DIR:-./pki}"
DEFAULT_ROOT_DAYS=3650
DEFAULT_INTER_DAYS=1825
DEFAULT_LEAF_DAYS=825      # <= 825 Tage: gängiges Limit für öffentl. TLS-Zerts, auch privat sinnvoll
DEFAULT_BITS=4096
NOPASS=0

err() { echo "Fehler: $*" >&2; exit 1; }
info() { echo "==> $*"; }

need_openssl() {
  command -v openssl >/dev/null 2>&1 || err "openssl nicht gefunden im PATH"
}

# ---------------------------------------------------------------------------
# Argument-Parsing-Helfer: liest --key value Paare aus dem Rest-Array
# ---------------------------------------------------------------------------
parse_opt() {
  local __var="$1"; shift
  local flag="$1"; shift
  local default="${1:-}"; shift || true
  local val="$default"
  local args=("$@")
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "$flag" ]]; then
      val="${args[$((i+1))]}"
    fi
  done
  printf -v "$__var" '%s' "$val"
}

has_flag() {
  local flag="$1"; shift
  for a in "$@"; do [[ "$a" == "$flag" ]] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------
# Erzeugt eine openssl.cnf für eine CA (root oder intermediate) im eigenen
# Verzeichnis. dir = pki/<name>, cn = Anzeigename im Zertifikat.
# ---------------------------------------------------------------------------
write_ca_cnf() {
  local dir="$1" cn="$2"
  cat > "$dir/ca.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $dir
certs             = \$dir/certs
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem
default_md        = sha256
default_days      = 825
policy            = policy_loose
copy_extensions   = none
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = $DEFAULT_BITS
default_md         = sha256
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
CN = $cn

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
EOF
}

# Leaf-Extensions werden NICHT in ca.cnf abgelegt (subjectAltName ist pro
# Zertifikat unterschiedlich und ${ENV::..}-Variablen würden schon beim
# Laden der Config global ausgewertet, auch wenn die Section nicht genutzt
# wird). Stattdessen pro Ausstellung eine temporäre Extension-Datei bauen.
write_leaf_ext() {
  local file="$1" kind="$2" san="$3"
  if [[ "$kind" == "server" ]]; then
    cat > "$file" <<EOF
basicConstraints        = CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth
subjectAltName          = $san
EOF
  else
    cat > "$file" <<EOF
basicConstraints        = CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = clientAuth
EOF
  fi
}

init_ca_dirs() {
  local dir="$1"
  mkdir -p "$dir"/{private,certs,csr,newcerts}
  chmod 700 "$dir/private"
  touch "$dir/index.txt"
  [[ -f "$dir/serial" ]] || echo 1000 > "$dir/serial"
}

genkey_args() {
  # gibt zusätzliche openssl-genpkey-Argumente für Passwortschutz zurück
  if [[ "$NOPASS" -eq 1 ]]; then
    echo ""
  else
    echo "-aes256"
  fi
}

# ---------------------------------------------------------------------------
# init-root <name> [--days N] [--bits N] [--nopass]
# ---------------------------------------------------------------------------
cmd_init_root() {
  local name="$1"; shift
  has_flag --nopass "$@" && NOPASS=1
  local days bits
  parse_opt days --days "$DEFAULT_ROOT_DAYS" "$@"
  parse_opt bits --bits "$DEFAULT_BITS" "$@"

  local dir="$BASE_DIR/$name"
  [[ -e "$dir" ]] && err "Verzeichnis $dir existiert bereits"
  init_ca_dirs "$dir"
  write_ca_cnf "$dir" "$name Root CA"

  info "Erzeuge privaten Root-Key ($bits bit, $( [[ $NOPASS -eq 1 ]] && echo unverschlüsselt || echo passwortgeschützt ))"
  # shellcheck disable=SC2046
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" \
    $(genkey_args) -out "$dir/private/ca.key.pem"
  chmod 400 "$dir/private/ca.key.pem"

  info "Erzeuge selbstsigniertes Root-Zertifikat (gültig $days Tage)"
  openssl req -config "$dir/ca.cnf" -key "$dir/private/ca.key.pem" \
    -new -x509 -days "$days" -sha256 -extensions v3_ca \
    -out "$dir/certs/ca.cert.pem"
  chmod 444 "$dir/certs/ca.cert.pem"

  info "Root-CA '$name' fertig: $dir/certs/ca.cert.pem"
}

# ---------------------------------------------------------------------------
# init-inter <name> --parent <parent> [--days N] [--bits N] [--nopass]
# ---------------------------------------------------------------------------
cmd_init_inter() {
  local name="$1"; shift
  has_flag --nopass "$@" && NOPASS=1
  local parent days bits
  parse_opt parent --parent "" "$@"
  [[ -z "$parent" ]] && err "--parent <ca-name> erforderlich"
  parse_opt days --days "$DEFAULT_INTER_DAYS" "$@"
  parse_opt bits --bits "$DEFAULT_BITS" "$@"

  local pdir="$BASE_DIR/$parent"
  [[ -d "$pdir" ]] || err "Parent-CA '$parent' nicht gefunden unter $pdir"

  local dir="$BASE_DIR/$name"
  [[ -e "$dir" ]] && err "Verzeichnis $dir existiert bereits"
  init_ca_dirs "$dir"
  write_ca_cnf "$dir" "$name Intermediate CA"

  info "Erzeuge privaten Intermediate-Key ($bits bit)"
  # shellcheck disable=SC2046
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" \
    $(genkey_args) -out "$dir/private/ca.key.pem"
  chmod 400 "$dir/private/ca.key.pem"

  info "Erzeuge CSR für Intermediate-CA"
  openssl req -config "$dir/ca.cnf" -new -sha256 \
    -key "$dir/private/ca.key.pem" \
    -out "$dir/csr/ca.csr.pem"

  info "Signiere Intermediate-CSR mit Parent-CA '$parent' (gültig $days Tage)"
  openssl ca -config "$pdir/ca.cnf" -extensions v3_intermediate_ca \
    -days "$days" -notext -md sha256 -batch \
    -in "$dir/csr/ca.csr.pem" -out "$dir/certs/ca.cert.pem"
  chmod 444 "$dir/certs/ca.cert.pem"

  info "Intermediate-CA '$name' (unter '$parent') fertig: $dir/certs/ca.cert.pem"
}

# ---------------------------------------------------------------------------
# issue-server / issue-client <cert-name> --parent <ca> --cn <cn> [--san ...] [--days N] [--bits N] [--nopass]
# ---------------------------------------------------------------------------
issue_leaf() {
  local kind="$1"; shift   # server | client
  local name="$1"; shift
  has_flag --nopass "$@" && NOPASS=1
  local parent cn san days bits
  parse_opt parent --parent "" "$@"
  parse_opt cn --cn "" "$@"
  parse_opt san --san "" "$@"
  parse_opt days --days "$DEFAULT_LEAF_DAYS" "$@"
  parse_opt bits --bits "2048" "$@"

  [[ -z "$parent" ]] && err "--parent <ca-name> erforderlich"
  [[ -z "$cn" ]] && err "--cn <common-name> erforderlich"

  local pdir="$BASE_DIR/$parent"
  [[ -d "$pdir" ]] || err "Ausstellende CA '$parent' nicht gefunden unter $pdir"

  local outdir="$pdir/issued/$name"
  mkdir -p "$outdir"

  info "Erzeuge privaten Key für '$name' ($bits bit, Typ: $kind)"
  # shellcheck disable=SC2046
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" \
    $(genkey_args) -out "$outdir/$name.key.pem"
  chmod 400 "$outdir/$name.key.pem"

  info "Erzeuge CSR (CN=$cn)"
  openssl req -new -sha256 -key "$outdir/$name.key.pem" \
    -subj "/CN=$cn" -out "$outdir/$name.csr.pem"

  local extfile="$outdir/$name.ext.cnf"
  if [[ "$kind" == "server" ]]; then
    [[ -z "$san" ]] && san="dns:$cn"
    # openssl-Notation: "dns:a,dns:b,ip:1.2.3.4" -> "DNS:a,DNS:b,IP:1.2.3.4"
    san=$(echo "$san" | sed -E 's/dns:/DNS:/gI; s/ip:/IP:/gI')
    write_leaf_ext "$extfile" server "$san"
    info "Signiere Server-Zertifikat mit CA '$parent' (SAN: $san, $days Tage)"
  else
    write_leaf_ext "$extfile" client ""
    info "Signiere Client-Zertifikat (mTLS) mit CA '$parent' ($days Tage)"
  fi
  openssl ca -config "$pdir/ca.cnf" -extfile "$extfile" \
    -days "$days" -notext -md sha256 -batch \
    -in "$outdir/$name.csr.pem" -out "$outdir/$name.cert.pem"
  chmod 444 "$outdir/$name.cert.pem"

  info "Fertig: $outdir/$name.cert.pem (Key: $outdir/$name.key.pem, Typ: $kind)"
}

cmd_issue_server() { issue_leaf server "$@"; }
cmd_issue_client() { issue_leaf client "$@"; }

# ---------------------------------------------------------------------------
# export-p12 <cert-name> --parent <ca> [--out <datei.p12>]
# Bündelt Client- (oder Server-)Key + Zertifikat + CA-Kette als PKCS#12,
# z. B. zum Import in macOS-Schlüsselbund/Browser für mTLS-Client-Zerts.
# ---------------------------------------------------------------------------
cmd_export_p12() {
  local name="$1"; shift
  local parent out
  parse_opt parent --parent "" "$@"
  parse_opt out --out "" "$@"
  [[ -z "$parent" ]] && err "--parent <ca-name> erforderlich"

  local pdir="$BASE_DIR/$parent"
  local dir="$pdir/issued/$name"
  local key="$dir/$name.key.pem"
  local cert="$dir/$name.cert.pem"
  [[ -f "$key" ]] || err "Key nicht gefunden: $key"
  [[ -f "$cert" ]] || err "Zertifikat nicht gefunden: $cert"

  [[ -z "$out" ]] && out="$dir/$name.p12"

  info "Erzeuge PKCS#12-Bundle für '$name' (Apple-kompatible Verschlüsselung; Passphrase des Keys wird ggf. abgefragt, danach neues Export-Passwort setzen)"
  # Wichtig für macOS/Keychain-Kompatibilität: neuere OpenSSL-Versionen (3.x)
  # verschlüsseln PKCS#12 standardmäßig mit PBES2/AES-256+SHA-256, was Apples
  # Security-Framework beim Import nicht zuverlässig mit dem Zertifikat
  # verknüpft (Import meldet Erfolg, der private Key bleibt aber unbenutzbar).
  # Legacy-Algorithmen (3DES/SHA1) sind breit kompatibel und funktionieren
  # zuverlässig mit Schlüsselbundverwaltung/Safari.
  openssl pkcs12 -export \
    -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
    -inkey "$key" \
    -in "$cert" \
    -certfile "$pdir/certs/ca.cert.pem" \
    -out "$out"

  chmod 400 "$out"
  info "Fertig: $out (zum Import in macOS-Schlüsselbund / Browser)"
}

# ---------------------------------------------------------------------------
# chain <cert-name> --parent <ca>   — baut Fullchain-Datei (Leaf + alle CAs
# bis zur Root, sofern die Parent-Kette lokal unter pki/ vorhanden ist)
# ---------------------------------------------------------------------------
cmd_chain() {
  local name="$1"; shift
  local parent
  parse_opt parent --parent "" "$@"
  [[ -z "$parent" ]] && err "--parent <ca-name> erforderlich"

  local pdir="$BASE_DIR/$parent"
  local leaf="$pdir/issued/$name/$name.cert.pem"
  [[ -f "$leaf" ]] || err "Leaf-Zertifikat nicht gefunden: $leaf"

  local out="$pdir/issued/$name/$name.fullchain.pem"
  rm -f "$out"
  cp "$leaf" "$out"
  chmod 644 "$out"

  # CA-Kette nach oben verfolgen: liest im ca.cnf jeder Stufe nichts über den
  # eigenen Parent, daher: Konvention nutzen, dass Intermediate-CAs mit
  # init-inter --parent angelegt wurden; wir laufen daher manuell die Kette
  # per Namensverzeichnis-Suche hoch, indem wir alle pki/*/certs/ca.cert.pem
  # durchsuchen und den Aussteller des jeweils letzten Zertifikats matchen.
  local current="$pdir/certs/ca.cert.pem"
  cat "$current" >> "$out"
  while true; do
    local issuer subj found=""
    issuer=$(openssl x509 -in "$current" -noout -issuer | sed 's/issuer=//')
    subj=$(openssl x509 -in "$current" -noout -subject | sed 's/subject=//')
    [[ "$issuer" == "$subj" ]] && break   # selbstsigniert = Root erreicht
    for cadir in "$BASE_DIR"/*/; do
      local cert="$cadir/certs/ca.cert.pem"
      [[ -f "$cert" ]] || continue
      local s
      s=$(openssl x509 -in "$cert" -noout -subject | sed 's/subject=//')
      if [[ "$s" == "$issuer" ]]; then
        found="$cert"
        break
      fi
    done
    [[ -z "$found" ]] && { info "Übergeordnetes CA-Zertifikat für Aussteller '$issuer' nicht lokal gefunden, breche ab."; break; }
    cat "$found" >> "$out"
    current="$found"
  done

  info "Fullchain geschrieben: $out"
  chmod 444 "$out"
}

# ---------------------------------------------------------------------------
# show <pfad-zu-pem>
# ---------------------------------------------------------------------------
cmd_show() {
  local f="$1"
  [[ -f "$f" ]] || err "Datei nicht gefunden: $f"
  openssl x509 -in "$f" -noout -text
}

usage() {
  sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
  need_openssl
  [[ $# -lt 1 ]] && { usage; exit 1; }
  local cmd="$1"; shift
  case "$cmd" in
    init-root)    cmd_init_root "$@" ;;
    init-inter)   cmd_init_inter "$@" ;;
    issue-server) cmd_issue_server "$@" ;;
    issue-client) cmd_issue_client "$@" ;;
    export-p12)   cmd_export_p12 "$@" ;;
    chain)        cmd_chain "$@" ;;
    show)         cmd_show "$@" ;;
    -h|--help|help) usage ;;
    *) err "Unbekannter Befehl: $cmd (siehe --help)" ;;
  esac
}

main "$@"
