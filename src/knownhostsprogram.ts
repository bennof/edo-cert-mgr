import { Command } from "commander";
import { homedir } from "node:os";
import { join } from "node:path";

import { select, input, password } from "@inquirer/prompts";
import chalk from "chalk";

import { KnownHosts } from "./knownhosts.js";

export function registerKnownHostsCommand(program: Command) {

  program
    .command("knownhosts")
    .description("knownhosts administration")
    .action(async () => {
      // always works in ~/.ssh, independent of --directory
      const sshDir = join(homedir(), ".ssh");
      const knownHosts = new KnownHosts(join(sshDir, "known_hosts"), sshDir);
      await knownHosts.load();

      while (true) {
        const action = await select({
          message: "known_hosts",
          choices: [
            { name: "list", value: "list" },
            { name: "add", value: "add" },
            { name: "remove", value: "remove" },
            { name: "exit", value: "exit" },
          ],
        });

        try {
          if (action === "list") {
            for (const entry of knownHosts.list()) {
              console.log(`${entry.hosts.join(",")} ${entry.keyType}`);
            }
          } else if (action === "add") {
            const host = await input({ message: "Host (user@host):", required: true });
            const port = await input({ message: "Port (empty for 22):", validate: v => v === "" || /^\d+$/.test(v) });
            const pass = await password({ message: "Password:", mask: true });
            const added = await knownHosts.add(host, pass, port ? Number(port) : undefined);
            console.log(chalk.green(`${host} added (${added.length} new host keys)`));
          } else if (action === "remove") {
            const host = await input({ message: "Host:", required: true });
            const port = await input({ message: "Port (empty for 22):", validate: v => v === "" || /^\d+$/.test(v) });
            await knownHosts.remove(host, port ? Number(port) : undefined);
            console.log(chalk.green(`${host} removed`));
          } else {
            return;
          }
        } catch (err) {
          console.error(chalk.red((err as Error).message));
        }
      }
    });
}
