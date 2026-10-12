#!/usr/bin/env node

import { Command } from "commander";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { registerKnownHostsCommand } from "./knownhostsprogram.js";
import { registerCertTreeCommand } from "./certtreeprogram.js";

const DEFAULT_DIRECTORY = "./pki";

// package.json is one level above src/ and dist/
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const program = new Command();

program
  .name("edo-cert-mgr")
  .description("private certificate authority (https, mTLS) and SSH known_hosts manager")
  .version(version)
  .option("-d, --directory <path>", "certificate directory", DEFAULT_DIRECTORY)
  .hook("preAction", () => {
    // node does not expand "~", the shell only does it for unquoted CLI arguments
    const directory = program.opts<{ directory: string }>().directory;
    program.setOptionValue("directory", directory.replace(/^~(?=\/|$)/, homedir()));
  });


registerKnownHostsCommand(program);
registerCertTreeCommand(program);

program.parse();
