import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type CertKind = "directory" | "root" | "intermediate" | "server" | "client";

const SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

// Defaults as in ca.sh
const ROOT_DAYS = 3650;
const INTERMEDIATE_DAYS = 1825;
const LEAF_DAYS = 825;
const CA_BITS = 4096;
const LEAF_BITS = 2048;

export class CertNode {
  children: CertNode[] = [];
  parent?: CertNode;

  constructor(
    public readonly name: string,
    public readonly kind: CertKind,
    public readonly certFile: string, // for the directory node: the directory itself
    public readonly cert?: X509Certificate
  ) {}

  get isCA(): boolean {
    return this.kind === "root" || this.kind === "intermediate";
  }

  get notAfter(): Date | undefined {
    return this.cert ? new Date(this.cert.validTo) : undefined;
  }

  // CA: <ca>/private/ca.key.pem, leaf: <name>.key.pem next to the certificate
  get keyFile(): string | undefined {
    if (this.isCA) return join(dirname(dirname(this.certFile)), "private", "ca.key.pem");
    if (this.cert) return this.certFile.replace(/\.cert\.pem$/, ".key.pem");
    return undefined;
  }

  // true for an intermediate whose issuing CA is not in the directory
  get parentMissing(): boolean {
    return this.kind === "intermediate" && this.parent?.kind === "directory";
  }
}

async function readCert(file: string): Promise<X509Certificate> {
  return new X509Certificate(await readFile(file));
}

async function subdirectories(dir: string): Promise<string[]> {
  if (!existsSync(dir)) {
    return [];
  }
  const entries = await readdir(dir, { withFileTypes: true });
  return entries.filter(e => e.isDirectory()).map(e => e.name).sort();
}

// Passphrases are handed to openssl via environment variables, never on the command line
async function openssl(args: string[], keyPass?: string, caPass?: string): Promise<void> {
  const env = { ...process.env, EDO_KEY_PASS: keyPass ?? "", EDO_CA_PASS: caPass ?? "" };
  try {
    await execFileAsync("openssl", args, { env });
  } catch (err) {
    // keep the readable lines, drop "Using configuration ..." and the internal "<n>:error:..." trace
    const stderr = ((err as { stderr?: string }).stderr ?? "")
      .split("\n")
      .filter(l => l.trim() && !l.startsWith("Using configuration") && !/^\d+:error:/.test(l))
      .join("\n");
    throw new Error(`openssl ${args[0]} failed${stderr ? `: ${stderr}` : ""}`);
  }
}

// Remove a half created directory if a step fails, so the name can be used again
async function cleanupOnError(dir: string, steps: () => Promise<void>): Promise<void> {
  try {
    await steps();
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
}

async function generateKey(file: string, bits: number, passphrase?: string): Promise<void> {
  const encrypt = passphrase ? ["-aes256", "-pass", "env:EDO_KEY_PASS"] : [];
  await openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", `rsa_keygen_bits:${bits}`, ...encrypt, "-out", file], passphrase);
  await chmod(file, 0o400);
}

function caConfig(dir: string, cn: string): string {
  return `[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${dir}
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
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
default_bits       = ${CA_BITS}
default_md         = sha256
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
CN = ${cn}

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
`;
}

function leafExtensions(kind: "server" | "client", san: string[]): string {
  const lines = [
    "basicConstraints        = CA:false",
    "subjectKeyIdentifier    = hash",
    "authorityKeyIdentifier  = keyid,issuer",
    "keyUsage                = critical, digitalSignature, keyEncipherment",
    `extendedKeyUsage        = ${kind === "server" ? "serverAuth" : "clientAuth"}`,
  ];
  if (kind === "server") {
    lines.push(`subjectAltName          = ${san.join(",")}`);
  }
  return lines.join("\n") + "\n";
}

// Every leaf gets a fullchain (ca.sh chain): leaf + all CAs up to the root; servers send it, and so do machine clients for mtls
async function writeFullchain(certFile: string, parent: CertNode): Promise<void> {
  await writeChain(certFile.replace(/\.cert\.pem$/, ".fullchain.pem"), [certFile], parent);
}

// nginx ssl_client_certificate needs the issuing CA and all CAs above it up to the root
async function writeMtlsBundle(ca: CertNode): Promise<string> {
  const bundle = join(dirname(ca.certFile), "ca.mtls.pem");
  await writeChain(bundle, [], ca);
  return bundle;
}

async function writeChain(out: string, files: string[], ca: CertNode | undefined): Promise<void> {
  for (; ca?.isCA; ca = ca.parent) {
    files.push(ca.certFile);
  }
  const pems = await Promise.all(files.map(f => readFile(f, "utf8")));
  await rm(out, { force: true });
  await writeFile(out, pems.join(""));
  await chmod(out, 0o444);
}

// ca.sh export-p12: legacy 3DES/SHA1, because macOS keychain imports AES encrypted p12 files without a usable key
// keyPassphrase: for keys created encrypted by ca.sh
async function writeP12(certFile: string, bundle: string, name: string, exportPassword: string, keyPassphrase?: string): Promise<void> {
  const p12 = certFile.replace(/\.cert\.pem$/, ".p12");
  await rm(p12, { force: true });
  await openssl(["pkcs12", "-export", "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1",
    "-inkey", certFile.replace(/\.cert\.pem$/, ".key.pem"), "-in", certFile, "-certfile", bundle,
    "-name", name, "-passin", "env:EDO_CA_PASS", "-passout", "env:EDO_KEY_PASS", "-out", p12], exportPassword, keyPassphrase);
  await chmod(p12, 0o400);
}

export class CertTree {
  top: CertNode;

  constructor(
    public readonly directory: string
  ) {
    this.top = new CertNode(`${basename(resolve(directory))}/`, "directory", directory);
  }

  // Layout as in ca.sh: <directory>/<ca>/certs/ca.cert.pem and <directory>/<ca>/issued/<name>/<name>.cert.pem
  async load(): Promise<void> {
    const cas: CertNode[] = [];

    for (const name of await subdirectories(this.directory)) {
      const caFile = join(this.directory, name, "certs", "ca.cert.pem");
      if (!existsSync(caFile)) {
        continue;
      }
      const cert = await readCert(caFile);
      const selfSigned = cert.checkIssued(cert) && cert.verify(cert.publicKey);
      const ca = new CertNode(name, selfSigned ? "root" : "intermediate", caFile, cert);

      // leaves live in the directory of their issuing CA
      const issuedDir = join(this.directory, name, "issued");
      for (const leafName of await subdirectories(issuedDir)) {
        const leafFile = join(issuedDir, leafName, `${leafName}.cert.pem`);
        if (!existsSync(leafFile)) {
          continue;
        }
        const leafCert = await readCert(leafFile);
        const kind = leafCert.keyUsage?.includes(SERVER_AUTH) ? "server" : "client";
        const leaf = new CertNode(leafName, kind, leafFile, leafCert);
        leaf.parent = ca;
        ca.children.push(leaf);
      }
      cas.push(ca);
    }

    // CAs lie side by side on disk, the hierarchy is only known from the certificates
    for (const ca of cas) {
      if (ca.kind === "root") {
        continue;
      }
      const parent = cas.find(p => p !== ca && ca.cert!.checkIssued(p.cert!) && ca.cert!.verify(p.cert!.publicKey));
      if (parent) {
        ca.parent = parent;
        parent.children.unshift(ca);
      }
    }

    this.top.children = cas.filter(ca => ca.parent === undefined);
    this.top.children.forEach(ca => ca.parent = this.top);
  }

  list(): CertNode[] {
    return [...this.top.children];
  }

  // ca.sh init-root
  async createRoot(name: string, passphrase?: string): Promise<void> {
    const dir = await this.createCaDirectory(name, `${name} Root CA`);
    const key = join(dir, "private", "ca.key.pem");
    const cert = join(dir, "certs", "ca.cert.pem");

    await cleanupOnError(dir, async () => {
      await generateKey(key, CA_BITS, passphrase);
      await openssl(["req", "-config", join(dir, "ca.cnf"), "-key", key, "-passin", "env:EDO_KEY_PASS",
        "-new", "-x509", "-days", String(ROOT_DAYS), "-sha256", "-extensions", "v3_ca", "-out", cert], passphrase);
      await chmod(cert, 0o444);
    });
  }

  // ca.sh init-inter
  async createIntermediate(parent: CertNode, name: string, passphrase?: string, parentPassphrase?: string): Promise<void> {
    const dir = await this.createCaDirectory(name, `${name} Intermediate CA`);
    const key = join(dir, "private", "ca.key.pem");
    const csr = join(dir, "csr", "ca.csr.pem");
    const cert = join(dir, "certs", "ca.cert.pem");

    await cleanupOnError(dir, async () => {
      await generateKey(key, CA_BITS, passphrase);
      await openssl(["req", "-config", join(dir, "ca.cnf"), "-new", "-sha256", "-key", key, "-passin", "env:EDO_KEY_PASS", "-out", csr], passphrase);
      await this.sign(parent, ["-extensions", "v3_intermediate_ca", "-days", String(INTERMEDIATE_DAYS), "-in", csr, "-out", cert], parentPassphrase);
      await chmod(cert, 0o444);
    });
  }

  // ca.sh issue-server / issue-client with --nopass; san entries like "dns:host" or "ip:1.2.3.4", plain names count as dns
  // exportPassword is needed for client certificates, they also get a .p12 for browsers and the keychain
  async createLeaf(parent: CertNode, kind: "server" | "client", name: string, cn: string, san: string[] = [], parentPassphrase?: string, exportPassword?: string): Promise<void> {
    if (kind === "client" && !exportPassword) {
      throw new Error("client certificates need an export password for the .p12 file");
    }
    const dir = join(dirname(dirname(parent.certFile)), "issued", name);
    if (existsSync(dir)) {
      throw new Error(`${dir} already exists`);
    }
    await mkdir(dir, { recursive: true });
    const key = join(dir, `${name}.key.pem`);
    const csr = join(dir, `${name}.csr.pem`);
    const ext = join(dir, `${name}.ext.cnf`);
    const cert = join(dir, `${name}.cert.pem`);

    const altNames = (san.length > 0 ? san : [cn]).map(s =>
      /^ip:/i.test(s) ? `IP:${s.slice(3)}` : `DNS:${s.replace(/^dns:/i, "")}`
    );
    await cleanupOnError(dir, async () => {
      // leaf keys stay unencrypted: servers must start unattended, client keys get exported as .p12 with its own password
      await generateKey(key, LEAF_BITS);
      await openssl(["req", "-new", "-sha256", "-key", key, "-subj", `/CN=${cn}`, "-out", csr]);
      await writeFile(ext, leafExtensions(kind, altNames));
      await this.sign(parent, ["-extfile", ext, "-days", String(LEAF_DAYS), "-in", csr, "-out", cert], parentPassphrase);
      await chmod(cert, 0o444);
      await writeFullchain(cert, parent);
      if (kind === "client") {
        await writeP12(cert, await writeMtlsBundle(parent), name, exportPassword!);
      }
    });
  }

  // Renew a certificate and everything below it with the existing keys and CSRs; parents first, so fullchains get the new CA certificates
  async update(
    node: CertNode,
    passphraseFor: (node: CertNode) => Promise<string | undefined>, // CA keys for signing, client keys for the .p12
    exportPasswordFor: (client: CertNode) => Promise<string>
  ): Promise<void> {
    if (node.kind === "directory") {
      throw new Error("the directory itself cannot be renewed");
    }
    const tmp = `${node.certFile}.new`;
    await rm(tmp, { force: true });
    try {
      if (node.kind === "root") {
        const dir = dirname(dirname(node.certFile));
        await openssl(["req", "-config", join(dir, "ca.cnf"), "-key", node.keyFile!, "-passin", "env:EDO_KEY_PASS",
          "-new", "-x509", "-days", String(ROOT_DAYS), "-sha256", "-extensions", "v3_ca", "-out", tmp], await passphraseFor(node));
      } else {
        const parent = node.parent;
        if (!parent?.isCA) {
          throw new Error(`issuing CA of ${node.name} is missing`);
        }
        const args = node.isCA
          ? ["-extensions", "v3_intermediate_ca", "-days", String(INTERMEDIATE_DAYS), "-in", join(dirname(dirname(node.certFile)), "csr", "ca.csr.pem")]
          : ["-extfile", node.certFile.replace(/\.cert\.pem$/, ".ext.cnf"), "-days", String(LEAF_DAYS), "-in", node.certFile.replace(/\.cert\.pem$/, ".csr.pem")];
        await this.sign(parent, [...args, "-out", tmp], await passphraseFor(parent));
      }
      await chmod(tmp, 0o444);
      await rename(tmp, node.certFile);
    } catch (err) {
      await rm(tmp, { force: true });
      throw err;
    }

    if (!node.isCA) {
      await writeFullchain(node.certFile, node.parent!);
    }
    if (node.kind === "client") {
      await writeP12(node.certFile, await writeMtlsBundle(node.parent!), node.name, await exportPasswordFor(node), await passphraseFor(node));
    }
    for (const child of node.children) {
      await this.update(child, passphraseFor, exportPasswordFor);
    }
  }

  // Delete a certificate with all its children; leaves live inside their CA directory, sub CAs lie next to it
  async delete(node: CertNode): Promise<void> {
    if (node.kind === "directory") {
      throw new Error("the directory itself cannot be deleted");
    }
    for (const child of node.children) {
      if (child.isCA) {
        await this.delete(child);
      }
    }
    await rm(node.isCA ? dirname(dirname(node.certFile)) : dirname(node.certFile), { recursive: true, force: true });
  }

  private async createCaDirectory(name: string, cn: string): Promise<string> {
    const dir = resolve(this.directory, name);
    if (existsSync(dir)) {
      throw new Error(`${dir} already exists`);
    }
    // recursive = mkdir -p, also creates the pki directory itself on the first write
    for (const sub of ["private", "certs", "csr", "newcerts"]) {
      await mkdir(join(dir, sub), { recursive: true });
    }
    await chmod(join(dir, "private"), 0o700);
    await writeFile(join(dir, "index.txt"), "");
    await writeFile(join(dir, "serial"), "1000\n");
    await writeFile(join(dir, "ca.cnf"), caConfig(dir, cn));
    return dir;
  }

  // openssl ca with a temporary copy of the parent's ca.cnf, because ca.sh wrote relative "dir" paths
  private async sign(parent: CertNode, args: string[], parentPassphrase?: string): Promise<void> {
    const caDir = resolve(dirname(dirname(parent.certFile)));
    const tmp = await mkdtemp(join(tmpdir(), "edo-ca-"));
    try {
      const config = (await readFile(join(caDir, "ca.cnf"), "utf8")).replace(/^dir\s*=.*$/m, `dir = ${caDir}`);
      await writeFile(join(tmp, "ca.cnf"), config);
      await openssl(["ca", "-config", join(tmp, "ca.cnf"), "-notext", "-md", "sha256", "-batch",
        "-passin", "env:EDO_CA_PASS", ...args], undefined, parentPassphrase);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }
}
