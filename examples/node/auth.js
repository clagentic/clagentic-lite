#!/usr/bin/env node
// clagentic-lite example: auth.js
//
// Tiny login() with one deliberately planted bug: normalizeEmail() trims and
// lowercases but does NOT reject embedded NUL bytes. See examples/README.md
// for the full demo plot.

"use strict";

function normalizeEmail(email) {
  // BUG: trim + toLowerCase does not reject embedded NUL or control bytes.
  return String(email).trim().toLowerCase();
}

function login(email, password) {
  const e = normalizeEmail(email);
  const users = {
    "admin@example.com": "hunter2",
    "user@example.com":  "hunter2",
  };
  return users[e] === password;
}

function main(argv) {
  if (argv.length < 4) {
    console.error("usage: node auth.js <email> <password>");
    return 2;
  }
  const [, , email, password] = argv;
  const normalized = normalizeEmail(email);
  const ok = login(email, password);
  console.log(`normalized: ${JSON.stringify(normalized)}`);
  console.log(`login ok:   ${ok}`);
  return ok ? 0 : 1;
}

if (require.main === module) {
  process.exit(main(process.argv));
}

module.exports = { normalizeEmail, login };
