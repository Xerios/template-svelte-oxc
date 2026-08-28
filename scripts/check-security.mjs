#!/usr/bin/env node
// Two checks the rest of the toolchain cannot make:
//
//   1. Oxlint only parses <script> blocks, so nothing reads Svelte markup.
//      {@html ...} is the XSS hole and no linter here will flag it.
//   2. Vite inlines every VITE_* variable into the client bundle. A secret
//      with that prefix is a published secret.
//
// Run with `pnpm check:security` (part of `pnpm check`).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import process from "node:process";

const ROOT = process.cwd();
const SECRET_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL)/i;
const ALLOW_HTML = /allow-html:/;

/** @type {string[]} */
const problems = [];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const files = walk(ROOT);

// 1. Unguarded {@html} in Svelte markup.
for (const file of files.filter((f) => f.endsWith(".svelte"))) {
  const lines = readFileSync(file, "utf8").split("\n");

  lines.forEach((line, index) => {
    if (!line.includes("{@html")) return;

    const previous = lines[index - 1] ?? "";
    if (ALLOW_HTML.test(line) || ALLOW_HTML.test(previous)) return;

    problems.push(
      `${relative(ROOT, file)}:${index + 1}  {@html} without justification. ` +
        `Sanitize the value, then annotate the line with <!-- allow-html: why -->.`,
    );
  });
}

// 2. Secret-looking names exposed to the client through the VITE_ prefix.
const envFiles = files.filter((f) => /(^|\/)\.env(\.|$)/.test(relative(ROOT, f)));

for (const file of envFiles) {
  readFileSync(file, "utf8")
    .split("\n")
    .forEach((line, index) => {
      const name = line.trim().split("=")[0];
      if (!name?.startsWith("VITE_")) return;
      if (!SECRET_NAME.test(name)) return;

      problems.push(
        `${relative(ROOT, file)}:${index + 1}  ${name} is inlined into the client ` +
          `bundle. Drop the VITE_ prefix and read it server-side.`,
      );
    });
}

if (problems.length > 0) {
  console.error(`Found ${problems.length} security issue(s):\n`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("");
  process.exit(1);
}

console.log(`Security checks passed on ${files.length} files.`);
