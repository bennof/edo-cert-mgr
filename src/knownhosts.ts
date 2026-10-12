import { execFile, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface KnownHostEntry {
  hosts: string[];
  keyType: string;
  key: string;
  marker?: string;
  comment?: string;
  hashed: boolean;
}

// Parse one known_hosts line: [marker] hosts keyType key [comment]
function parseLine(line: string): KnownHostEntry | undefined {
  const fields = line.trim().split(/\s+/);
  if (fields[0] === "" || fields[0]?.startsWith("#")) {
    return undefined;
  }
  const marker = fields[0]?.startsWith("@") ? fields.shift() : undefined;
  const [hosts, keyType, key, ...comment] = fields;
  if (!hosts || !keyType || !key) {
    return undefined;
  }

  const entry: KnownHostEntry = { hosts: hosts.split(","), keyType, key, hashed: hosts.startsWith("|1|") };
  if (marker) entry.marker = marker;
  if (comment.length > 0) entry.comment = comment.join(" ");
  return entry;
}

const SSH_CONFIG = join(homedir(), ".ssh", "config");

// Remove the "Host <hostname>" block (up to the next Host/Match line) from ~/.ssh/config
async function removeConfigBlock(hostname: string): Promise<void> {
  if (!existsSync(SSH_CONFIG)) {
    return;
  }
  const lines = (await readFile(SSH_CONFIG, "utf8")).split("\n");
  const start = lines.findIndex(l => l.trim() === `Host ${hostname}`);
  if (start === -1) {
    return;
  }
  let end = lines.findIndex((l, i) => i > start && /^\s*(Host|Match)\s/i.test(l));
  if (end === -1) end = lines.length;
  // also drop the empty line written before the block
  const from = start > 0 && lines[start - 1]?.trim() === "" ? start - 1 : start;
  lines.splice(from, end - from);
  await writeFile(SSH_CONFIG, lines.join("\n").replace(/\n*$/, "\n"));
}

export class KnownHosts {
  private entries: KnownHostEntry[] = [];

  constructor(
    public readonly path: string,
    public readonly keyDirectory: string
  ) {}

  async load(): Promise<void> {
    // create a representation of the known_hosts file in memory
    const content = existsSync(this.path) ? await readFile(this.path, "utf8") : "";
    this.entries = content
      .split(/\r?\n/)
      .map(parseLine)
      .filter((entry): entry is KnownHostEntry => entry !== undefined);
    return;
  }

  list(): KnownHostEntry[] {
    return [...this.entries];
  }

  // host may be given as "user@host"
  async add(host: string, password: string, port?: number): Promise<KnownHostEntry[]> {
    // check if key exists else create key, add it to ~/.ssh/config and copy it to host
    const [user, hostname] = host.includes("@") ? host.split("@") as [string, string] : [undefined, host];
    if (port === 22) port = undefined; // known_hosts writes the default port without [host]:port
    const pattern = port ? `[${hostname}]:${port}` : hostname;
    const keyFile = join(this.keyDirectory, `id_ed25519_${port ? `${hostname}_${port}` : hostname}`);

    if (!existsSync(keyFile)) {
      await mkdir(this.keyDirectory, { recursive: true, mode: 0o700 });
      await execFileAsync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", keyFile]);
    }

    // add host key to known_hosts unless already present (ssh-keygen -F exits 1 if not found)
    let added: KnownHostEntry[] = [];
    if (spawnSync("ssh-keygen", ["-F", pattern, "-f", this.path]).status !== 0) {
      const { stdout } = await execFileAsync("ssh-keyscan", port ? ["-p", String(port), hostname] : [hostname]);
      added = stdout
        .split(/\r?\n/)
        .map(parseLine)
        .filter((entry): entry is KnownHostEntry => entry !== undefined);
      if (added.length === 0) {
        throw new Error(`ssh-keyscan returned no keys for ${pattern}`);
      }
      await appendFile(this.path, added.map(e => `${e.hosts.join(",")} ${e.keyType} ${e.key}\n`).join(""));
      await this.load();
    }

    // replace an existing Host block, so ssh uses this key and known_hosts file
    await removeConfigBlock(hostname);
    const block = [`Host ${hostname}`, `  HostName ${hostname}`];
    if (port) block.push(`  Port ${port}`);
    if (user) block.push(`  User ${user}`);
    block.push(`  IdentityFile ${resolve(keyFile)}`, "  IdentitiesOnly yes", `  UserKnownHostsFile ${resolve(this.path)}`);
    await mkdir(dirname(SSH_CONFIG), { recursive: true, mode: 0o700 });
    await appendFile(SSH_CONFIG, `\n${block.join("\n")}\n`, { mode: 0o600 });

    // ssh-copy-id reads the password from an askpass script instead of the terminal
    const askpassDir = await mkdtemp(join(tmpdir(), "edo-askpass-"));
    const askpass = join(askpassDir, "askpass.sh");
    try {
      await writeFile(askpass, `#!/bin/sh\nprintf '%s\\n' "$EDO_SSH_PASSWORD"\n`, { mode: 0o700 });
      const copyArgs = ["-i", `${keyFile}.pub`, "-o", `UserKnownHostsFile=${this.path}`];
      if (port) copyArgs.push("-p", String(port));
      const result = spawnSync("ssh-copy-id", [...copyArgs, host], {
        stdio: ["ignore", "inherit", "inherit"],
        env: {
          ...process.env,
          EDO_SSH_PASSWORD: password,
          SSH_ASKPASS: askpass,
          SSH_ASKPASS_REQUIRE: "force",
          DISPLAY: process.env.DISPLAY ?? ":0",
        },
      });
      if (result.status !== 0) {
        throw new Error(`ssh-copy-id failed for ${host}`);
      }
    } finally {
      await rm(askpassDir, { recursive: true, force: true });
    }

    return added;
  }

  async remove(host: string, port?: number): Promise<void> {
    // remove key from known_hosts file and from memory representation and delete certificate if it exists
    const hostname = host.split("@").pop()!;
    if (port === 22) port = undefined;
    const keyFile = join(this.keyDirectory, `id_ed25519_${port ? `${hostname}_${port}` : hostname}`);

    if (existsSync(this.path)) {
      await execFileAsync("ssh-keygen", ["-R", port ? `[${hostname}]:${port}` : hostname, "-f", this.path]);
    }
    await this.load();
    await removeConfigBlock(hostname);

    for (const file of [keyFile, `${keyFile}.pub`, `${keyFile}-cert.pub`]) {
      await rm(file, { force: true });
    }
  }
}
