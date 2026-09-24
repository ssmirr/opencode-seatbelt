import { createRequire } from "node:module"
import { Plugin } from "@opencode/plugin"
import {
  buildProfile,
  defaultGlobalDir,
  discoverPolicy,
  warnOnGlobNegation,
  type PolicySource,
  type SeatbeltOptions,
} from "./policy.ts"

const LIBSANDBOX = "/usr/lib/libsandbox.dylib"
const PREFIX = "[opencode-seatbelt]"

type BunFfi = typeof import("bun:ffi")

/**
 * Seatbelt is reached through Bun's built-in FFI (`bun:ffi`). OpenCode is
 * distributed as a Bun-compiled binary — installing it with npm, Homebrew, or
 * the install script all download the same Bun runtime — so the plugin always
 * has `bun:ffi` in practice. It is loaded lazily anyway, so a host running on
 * plain Node fails with a loud warning instead of an unresolved-import crash.
 */
function loadFfi(): BunFfi | null {
  try {
    return createRequire(import.meta.url)("bun:ffi") as BunFfi
  } catch {
    return null
  }
}

/**
 * Seatbelt confinement is process-wide and irreversible, so it is applied at
 * most once. A second `sandbox_init` on an already-confined process fails with
 * EPERM; we treat that as "already active" rather than an error.
 */
let applied = false

export default Plugin.define({
  id: "opencode-seatbelt",
  setup(ctx) {
    const opts = (ctx.options ?? {}) as SeatbeltOptions
    const log = opts.log !== false
    const info = (message: string) => {
      if (log) console.log(`${PREFIX} ${message}`)
    }
    const warn = (message: string) => {
      if (log) console.warn(`${PREFIX} ${message}`)
    }

    const sessionDir = ctx.location?.directory ?? process.cwd()
    const projectDir = ctx.location?.project?.directory ?? sessionDir

    if (process.platform !== "darwin") {
      warn("only macOS (Seatbelt) is supported; skipping. Linux/Landlock support is not implemented yet.")
      return
    }

    if (applied) {
      warn("a Seatbelt profile is already applied in this process; ignoring this setup. Restart OpenCode to change policy.")
      return
    }

    let sources: PolicySource[]
    let policyFiles: string[]
    try {
      const discovered = discoverPolicy({
        sessionDir,
        projectDir,
        globalDir: defaultGlobalDir(),
        file: opts.file,
        baseline: opts.baseline !== false,
        discover: opts.discover !== false,
        subdirectories: opts.subdirectories !== false,
        skip: opts.skipDirectories,
        maxFiles: opts.maxFiles,
        extra: opts.extraPatterns,
        allow: opts.allowPatterns,
      })
      sources = discovered.sources
      policyFiles = discovered.files
    } catch (error) {
      warn(`could not read policy: ${(error as Error).message}`)
      return
    }

    const denyCount = sources.reduce((total, source) => total + source.deny.length, 0)
    const allowCount = sources.reduce((total, source) => total + source.allow.length, 0)

    if (policyFiles.length === 0) {
      if (opts.baseline === false) {
        warn("no policy files found and baseline is disabled; nothing to enforce.")
        return
      }
      warn("no policy files found; enforcing the built-in secret baseline only.")
    } else {
      info(`${policyFiles.length} policy file(s): ${policyFiles.join(", ")}`)
    }

    for (const source of sources) {
      for (const pattern of warnOnGlobNegation(source)) {
        warn(`negation "!${pattern}" (in ${source.path}) contains a glob; Seatbelt precedence may not honor it as you expect.`)
      }
    }

    const profile = buildProfile({
      sources,
      protectPolicyFiles: opts.protectPolicyFile === false ? [] : policyFiles,
    })

    if (opts.mode === "warn") {
      info(`dry run (${denyCount} deny, ${allowCount} allow):`)
      if (log) console.log(profile)
      return
    }

    const ffi = loadFfi()
    if (!ffi) {
      // Security-critical: never silence this even when `log: false`.
      console.warn(
        `${PREFIX} this host is not running on Bun, so bun:ffi is unavailable and the sandbox was NOT applied. ` +
          "OpenCode ships a Bun-compiled binary; install it from the official distribution (npm, Homebrew, or the install script).",
      )
      return
    }

    try {
      const { symbols } = ffi.dlopen(LIBSANDBOX, {
        sandbox_init: { args: ["cstring", "u64", "ptr"], returns: "int" },
      })
      const err = new BigUint64Array(1)
      const rc = symbols.sandbox_init(Buffer.from(profile + "\0"), 0n, err)
      if (rc !== 0) {
        const detail = err[0] ? new ffi.CString(Number(err[0])).toString() : `rc=${rc}`
        warn(`could not apply sandbox (${detail}). This usually means the process is already sandboxed; restart OpenCode.`)
        return
      }
      applied = true
      info(`sandbox active in ${sessionDir} — ${denyCount} deny, ${allowCount} allow.`)
      info("denied reads are enforced by the kernel for every tool, process, and path alias.")
    } catch (error) {
      warn(`could not apply sandbox: ${(error as Error).message}`)
    }
  },
})
