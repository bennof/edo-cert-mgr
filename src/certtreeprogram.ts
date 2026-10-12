import { Command } from "commander";
import { readFile } from "node:fs/promises";

import { confirm, input, password, select } from "@inquirer/prompts";
import chalk from "chalk";

import { CertNode, CertTree } from "./certtree.js";
import { selectNode } from "./treeprompt.js";

async function askParentPassphrase(parent: CertNode): Promise<string | undefined> {
  const key = await readFile(parent.keyFile!, "utf8");
  if (!key.includes("ENCRYPTED")) {
    return undefined;
  }
  return password({ message: `Passphrase of ${parent.name}:`, mask: true });
}

// p12 export password, entered twice; macOS and iOS refuse p12 files without password
async function askExportPassword(name: string): Promise<string> {
  while (true) {
    const first = await password({ message: `Export password for ${name}.p12:`, mask: true, validate: v => v.length > 0 || "required" });
    const second = await password({ message: "Repeat export password:", mask: true });
    if (first === second) {
      return first;
    }
    console.log(chalk.red("passwords do not match"));
  }
}

async function newCertificate(tree: CertTree, node: CertNode): Promise<void> {
  if (node.kind === "directory") {
    const name = await input({ message: "Name of the root CA:", required: true });
    const passphrase = await password({ message: "Passphrase for the new key (empty = unencrypted):", mask: true });
    await tree.createRoot(name, passphrase || undefined);
    return;
  }

  const type = await select({
    message: `new below ${node.name}`,
    choices: [
      { name: "intermediate CA", value: "intermediate" },
      { name: "mtls (client certificate)", value: "client" },
      { name: "https (server certificate)", value: "server" },
    ],
  });
  const name = await input({ message: "Name:", required: true });

  if (type === "intermediate") {
    const passphrase = await password({ message: "Passphrase for the new key (empty = unencrypted):", mask: true });
    const parentPassphrase = await askParentPassphrase(node);
    await tree.createIntermediate(node, name, passphrase || undefined, parentPassphrase);
    return;
  }

  const cn = await input({ message: type === "server" ? "Hostname (CN):" : "Username (CN):", default: name });
  const san = type === "server"
    ? (await input({ message: "Additional names (comma separated, ip:1.2.3.4 for IPs):" })).split(",").map(s => s.trim()).filter(Boolean)
    : [];
  const exportPassword = type === "client" ? await askExportPassword(name) : undefined;
  const parentPassphrase = await askParentPassphrase(node);
  await tree.createLeaf(node, type, name, cn, san.length > 0 ? [cn, ...san] : [], parentPassphrase, exportPassword);
}

export function registerCertTreeCommand(program: Command) {

  program
    .command("tree")
    .description("show certificate tree")
    .action(async (_options, command: Command) => {
      const { directory } = command.optsWithGlobals<{ directory: string }>();
      const tree = new CertTree(directory);
      await tree.load();

      const collapsed = new Set<CertNode>();
      let current: CertNode | undefined;
      while (true) {
        current = await selectNode({ message: directory, roots: [tree.top], collapsed, default: current });
        if (!current) {
          return;
        }

        // new: only on the directory and on CAs; update/delete: only on certificates
        const choices = [];
        if (current.kind === "directory" || current.isCA) choices.push({ name: "new", value: "new" });
        if (current.kind !== "directory") choices.push({ name: "update", value: "update" }, { name: "delete", value: "delete" });
        choices.push({ name: "back", value: "back" });

        const action = await select({ message: `${current.name} (${current.kind})`, choices });
        try {
          if (action === "new") {
            await newCertificate(tree, current);
            await tree.load();
            collapsed.clear();
            current = undefined;
            console.log(chalk.green("created"));
          } else if (action === "delete") {
            const names: string[] = [];
            const collect = (n: CertNode): void => { names.push(n.name); n.children.forEach(collect); };
            collect(current);
            const ok = await confirm({ message: `Delete ${names.join(", ")}? This cannot be undone.`, default: false });
            if (ok) {
              await tree.delete(current);
              await tree.load();
              collapsed.clear();
              current = undefined;
              console.log(chalk.green("deleted"));
            }
          } else if (action === "update") {
            const names: string[] = [];
            const collect = (n: CertNode): void => { names.push(n.name); n.children.forEach(collect); };
            collect(current);
            const ok = await confirm({ message: `Renew ${names.join(", ")}?`, default: false });
            if (ok) {
              // ask every encrypted CA only once
              const passphrases = new Map<CertNode, string | undefined>();
              await tree.update(current, async ca => {
                if (!passphrases.has(ca)) passphrases.set(ca, await askParentPassphrase(ca));
                return passphrases.get(ca);
              }, client => askExportPassword(client.name));
              await tree.load();
              collapsed.clear();
              current = undefined;
              console.log(chalk.green("renewed"));
            }
          }
        } catch (err) {
          console.error(chalk.red((err as Error).message));
        }
      }
    });
}
