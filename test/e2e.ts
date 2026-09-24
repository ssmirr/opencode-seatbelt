/**
 * End-to-end verifier for the compiled Seatbelt profile.
 *
 * Applies the real profile to THIS process, then checks which reads succeed.
 * It must run in a process that is not already sandboxed (i.e. your terminal,
 * not inside an OpenCode session that already loaded the plugin), because
 * `sandbox_init` can only be applied once per process.
 *
 *   bun run test/e2e.ts
 *
 * Set OC_E2E_NO_SANDBOX=1 to skip applying the sandbox and just print the plan
 * (useful for checking discovery without confining anything).
 */

import { linkSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { dlopen, CString } from "bun:ffi"
import { buildProfile, discoverPolicy } from "../src/policy.ts"

const base = mkdtempSync(join(tmpdir(), "oc-seatbelt-e2e-"))
const globalDir = join(base, "home", ".config", "opencode")
const repo = join(base, "repo")
const pkg = join(repo, "pkg")
const deep = join(pkg, "deep")
const nm = join(repo, "node_modules")
const outside = join(base, "outside")

for (const dir of [globalDir, deep, nm, outside]) mkdirSync(dir, { recursive: true })

const write = (path: string, text: string) => writeFileSync(path, text)

write(join(globalDir, ".ocignore"), "global.secret\n")
write(join(repo, ".ocignore"), "goozoo\nsecret.txt\n!public.txt\n")
write(join(pkg, ".ocignore"), "pkg.secret\n")
write(join(deep, ".ocignore"), "deep.secret\n")
write(join(nm, ".ocignore"), "skipped.secret\n")

write(join(repo, "goozoo"), "GOOZOO")
write(join(pkg, "goozoo"), "GOOZOO-IN-PKG")
write(join(repo, "secret.txt"), "SECRET")
write(join(repo, "public.txt"), "PUBLIC")
write(join(pkg, "pkg.secret"), "PKG")
write(join(deep, "deep.secret"), "DEEP")
write(join(repo, "pkg.secret"), "SCOPED-OUT")
write(join(repo, "global.secret"), "GLOBAL")
write(join(pkg, "global.secret"), "GLOBAL-IN-PKG")
write(join(nm, "skipped.secret"), "SKIPPED")
write(join(repo, "notes.txt"), "hi")
write(join(repo, ".env"), "ENV")
write(join(repo, ".env.example"), "EXAMPLE")
write(join(outside, ".env"), "OUTSIDE") // baseline is global -> denied anywhere
write(join(outside, "goozoo"), "OUTSIDE-GOOZOO") // repo scope does not reach here

const discovered = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir })
const policyFiles = discovered.files
const profile = buildProfile({ sources: discovered.sources, protectPolicyFiles: policyFiles })

console.log("policy files discovered (lowest -> highest precedence):")
for (const source of discovered.sources) {
  console.log(`  ${source.kind.padEnd(9)} root=${source.root ?? "(anywhere)"}  ${source.path}`)
}
console.log()

if (process.env.OC_E2E_NO_SANDBOX === "1") {
  console.log("OC_E2E_NO_SANDBOX=1 set — not applying the sandbox. Profile:\n")
  console.log(profile)
  process.exit(0)
}

const { symbols } = dlopen("/usr/lib/libsandbox.dylib", {
  sandbox_init: { args: ["cstring", "u64", "ptr"], returns: "int" },
})
const err = new BigUint64Array(1)
const rc = symbols.sandbox_init(Buffer.from(profile + "\0"), 0n, err)
if (rc !== 0) {
  console.error(`sandbox_init failed rc=${rc} ${err[0] ? new CString(Number(err[0])).toString() : ""}`)
  console.error("(This means the process was already sandboxed — run this from a plain terminal.)")
  process.exit(2)
}
console.log("sandbox_init OK — the rest of this process is confined.\n")

const expectRead = [
  "pkg.secret (sibling of pkg/, outside its scope)",
  "public.txt (negation)",
  "notes.txt (plain)",
  ".env.example (baseline allow)",
  "node_modules/skipped.secret (skip dir)",
  "outside/goozoo (outside project scope)",
]
const expectDeny = [
  "goozoo (repo root)",
  "pkg/goozoo (repo source covers subdir)",
  "secret.txt (repo root)",
  "pkg/pkg.secret (nested source)",
  "pkg/deep/deep.secret (nested source)",
  "global.secret (global source, anywhere)",
  "pkg/global.secret (global source, anywhere)",
  ".env (baseline)",
  "outside/.env (baseline is global)",
]

const rel = (p: string) => p.slice(base.length + 1)
const cases: Array<{ label: string; path: string; read: boolean }> = [
  { label: expectRead[0]!, path: join(repo, "pkg.secret"), read: true },
  { label: expectRead[1]!, path: join(repo, "public.txt"), read: true },
  { label: expectRead[2]!, path: join(repo, "notes.txt"), read: true },
  { label: expectRead[3]!, path: join(repo, ".env.example"), read: true },
  { label: expectRead[4]!, path: join(nm, "skipped.secret"), read: true },
  { label: expectRead[5]!, path: join(outside, "goozoo"), read: true },
  { label: expectDeny[0]!, path: join(repo, "goozoo"), read: false },
  { label: expectDeny[1]!, path: join(pkg, "goozoo"), read: false },
  { label: expectDeny[2]!, path: join(repo, "secret.txt"), read: false },
  { label: expectDeny[3]!, path: join(pkg, "pkg.secret"), read: false },
  { label: expectDeny[4]!, path: join(deep, "deep.secret"), read: false },
  { label: expectDeny[5]!, path: join(repo, "global.secret"), read: false },
  { label: expectDeny[6]!, path: join(pkg, "global.secret"), read: false },
  { label: expectDeny[7]!, path: join(repo, ".env"), read: false },
  { label: expectDeny[8]!, path: join(outside, ".env"), read: false },
]

let failures = 0
let checks = 0
const report = (outcome: string, ok: boolean, label: string, detail: string) => {
  checks++
  if (!ok) failures++
  console.log(`${ok ? "PASS" : "FAIL"}  ${outcome.padEnd(4)}  ${label.padEnd(52)} ${detail}`)
}

for (const c of cases) {
  let got: string
  try {
    readFileSync(c.path, "utf8")
    got = "READ"
  } catch (error) {
    got = (error as NodeJS.ErrnoException).code === "EPERM" ? "DENY" : `ERR ${(error as Error).message}`
  }
  const want = c.read ? "READ" : "DENY"
  report(got, got === want, c.label, `${rel(c.path)}`)
}

// Policy files must be protected from writes.
let writeDenied = false
try {
  writeFileSync(join(repo, ".ocignore"), "tampered\n")
} catch (error) {
  writeDenied = (error as NodeJS.ErrnoException).code === "EPERM"
}
report(writeDenied ? "DENY" : "READ", writeDenied, "policy file is write-protected", rel(join(repo, ".ocignore")))

// A denied file must not be launderable into an allowed path. If the read deny
// also covers the source lookup, rename()/link() fail with EPERM too.
const denied = (run: () => void): boolean => {
  try {
    run()
    return false
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM"
  }
}
const renameDenied = denied(() => renameSync(join(repo, "goozoo"), join(outside, "goozoo.moved")))
const linkDenied = denied(() => linkSync(join(repo, "secret.txt"), join(outside, "secret.link")))
report(renameDenied ? "DENY" : "READ", renameDenied, "denied file cannot be renamed out", "goozoo")
report(linkDenied ? "DENY" : "READ", linkDenied, "denied file cannot be hardlinked out", "secret.txt")

try {
  rmSync(base, { recursive: true, force: true })
} catch {
  // Best effort: the sandbox may block the metadata reads an rm needs on denied entries.
}

console.log()
console.log(failures === 0 ? `ALL PASS (${checks} checks)` : `${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
