#!/usr/bin/env node
// `deedroll` on npm is a pointer to @antharmaya/deedroll: it holds the short
// name and runs the real CLI, so there is one implementation to keep current.
const entry = import.meta.resolve('@antharmaya/deedroll');
await import(new URL('../bin/deedroll.js', entry).href);
