import { createPrompt, isDownKey, isEnterKey, isUpKey, useKeypress, usePagination, usePrefix, useState } from "@inquirer/core";
import chalk from "chalk";

import type { CertNode } from "./certtree.js";

interface TreeLine {
  node: CertNode;
  text: string;
}

function label(node: CertNode, collapsed: Set<CertNode>): string {
  const toggle = node.children.length > 0 ? (collapsed.has(node) ? "▸ " : "▾ ") : "  ";
  if (!node.notAfter) {
    return toggle + chalk.bold(node.name);
  }
  const date = node.notAfter.toISOString().slice(0, 10);
  const details = [
    node.isCA ? chalk.bold(node.name) : node.name,
    chalk.dim(node.kind),
    node.notAfter < new Date() ? chalk.red(`expired ${date}`) : chalk.dim(`until ${date}`),
  ];
  if (node.parentMissing) details.push(chalk.yellow("parent missing"));
  return toggle + details.join("  ");
}

// Visible nodes with tree connectors; collapsed nodes hide their children
function flatten(nodes: CertNode[], collapsed: Set<CertNode>, prefix = ""): TreeLine[] {
  return nodes.flatMap((node, i) => {
    const last = i === nodes.length - 1;
    const line = { node, text: `${prefix}${last ? "└── " : "├── "}${label(node, collapsed)}` };
    if (collapsed.has(node)) {
      return [line];
    }
    return [line, ...flatten(node.children, collapsed, prefix + (last ? "    " : "│   "))];
  });
}

export interface SelectNodeConfig {
  message: string;
  roots: CertNode[];
  collapsed: Set<CertNode>; // shared, so the state survives between calls
  default?: CertNode | undefined;
  pageSize?: number;
}

// ↑↓ move, → expand, ← collapse or jump to parent, Enter selects, q/Esc returns undefined
export const selectNode = createPrompt<CertNode | undefined, SelectNodeConfig>((config, done) => {
  const [status, setStatus] = useState("idle");
  const [collapsed, setCollapsed] = useState(new Set(config.collapsed));
  const [active, setActive] = useState(config.default ?? config.roots[0]);
  const [chosen, setChosen] = useState<CertNode | undefined>(undefined);
  const prefix = usePrefix({ status });

  const lines = flatten(config.roots, collapsed);
  const index = Math.max(0, lines.findIndex(l => l.node === active));

  const finish = (node: CertNode | undefined) => {
    config.collapsed.clear();
    collapsed.forEach(n => config.collapsed.add(n));
    setChosen(node);
    setStatus("done");
    done(node);
  };

  const toggle = (node: CertNode, collapse: boolean) => {
    const next = new Set(collapsed);
    if (collapse) next.add(node); else next.delete(node);
    setCollapsed(next);
  };

  useKeypress(key => {
    const node = lines[index]?.node;
    if (!node) {
      return;
    }
    if (isEnterKey(key)) {
      finish(node);
    } else if (key.name === "q" || key.name === "escape") {
      finish(undefined);
    } else if (isUpKey(key)) {
      setActive(lines[Math.max(0, index - 1)]!.node);
    } else if (isDownKey(key)) {
      setActive(lines[Math.min(lines.length - 1, index + 1)]!.node);
    } else if (key.name === "right" && collapsed.has(node)) {
      toggle(node, false);
    } else if (key.name === "left") {
      if (node.children.length > 0 && !collapsed.has(node)) {
        toggle(node, true);
      } else if (node.parent) {
        setActive(node.parent);
      }
    }
  });

  const page = usePagination({
    items: lines,
    active: index,
    renderItem: ({ item, isActive }) => (isActive ? chalk.cyan("❯ ") : "  ") + item.text,
    pageSize: config.pageSize ?? 20,
    loop: false,
  });

  if (status === "done") {
    return `${prefix} ${config.message} ${chalk.cyan(chosen?.name ?? "")}`;
  }

  const help = chalk.dim("↑↓ move • ←→ collapse/expand • ⏎ select • q quit");
  return `${prefix} ${chalk.bold(config.message)}\n${page}\n${help}`;
});
