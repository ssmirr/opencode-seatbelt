/**
 * .ocignore policy compilation and discovery.
 *
 * Two jobs:
 *   1. Discover every `.ocignore` that applies to a session (global config dir,
 *      ancestors from the session directory up to the filesystem root, and
 *      nested files in subdirectories).
 *   2. Compile the union of those patterns into a macOS Seatbelt (SBPL) profile.
 *
 * Patterns are compiled to *regexes* rather than an enumeration of existing
 * files, so files created after startup are still matched. Each file's patterns
 * are scoped to that file's own directory, except the built-in baseline and the
 * global file, which match anywhere. The profile is applied once per process and
 * cannot be changed afterwards — see README for the restart caveat.
 */

import { readdirSync, readFileSync, realpathSync } from "node:fs"
import { homedir } from "node:os"
import { join, resolve, sep } from "node:path"

/** Name of the default policy file. */
export const DEFAULT_POLICY_FILE = ".ocignore"

/**
 * Secret-shaped patterns always denied unless `baseline: false` is set.
 * These protect you even when a repository forgets to list something in
 * .ocignore, which is the common real-world failure mode. The baseline is
 * global: it matches at any depth, anywhere on the filesystem.
 */
export const BASELINE_DENY: readonly string[] = [
  "*.env",
  "*.env.*",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  "credentials",
  "credentials.json",
  ".ssh/",
  ".aws/",
  ".gnupg/",
]

/** Patterns re-allowed even though the baseline denies them. */
export const BASELINE_ALLOW: readonly string[] = [".env.example", ".env.sample", ".env.template"]

/** Directory names skipped while scanning downward for nested policy files. */
export const DEFAULT_SKIP_DIRECTORIES: readonly string[] = [
  ".git",
  "node_modules",
  ".venv",
  "venv",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "target",
  "vendor",
  "__pycache__",
  ".cache",
  ".turbo",
  ".gradle",
  ".idea",
  ".vscode",
]

export interface SeatbeltOptions {
  /** Policy file name searched in each directory. Default: ".ocignore". */
  file?: string
  /** Include the built-in secret baseline. Default: true. */
  baseline?: boolean
  /** Extra deny patterns, in .ocignore subset syntax. */
  extraPatterns?: string[]
  /** Extra allow (negation) patterns. */
  allowPatterns?: string[]
  /** "enforce" (default) applies the sandbox; "warn" only prints the profile. */
  mode?: "enforce" | "warn"
  /** Deny writes to every discovered policy file so the agent cannot pre-edit it. Default: true. */
  protectPolicyFile?: boolean
  /** Print sandbox status lines. Default: true. */
  log?: boolean
  /**
   * Discover policy files beyond the project root: the global config file,
   * ancestors up to the filesystem root, and nested files. Default: true.
   */
  discover?: boolean
  /** Scan subdirectories for nested policy files. Default: true. */
  subdirectories?: boolean
  /** Directory names skipped while scanning downward. Default: DEFAULT_SKIP_DIRECTORIES. */
  skipDirectories?: string[]
  /** Safety cap on the number of discovered policy files. Default: 256. */
  maxFiles?: number
}

export interface PatternSet {
  deny: string[]
  allow: string[]
}

/** A set of patterns together with the directory they are scoped to. */
export interface PolicySource extends PatternSet {
  /**
   * Absolute directory that anchored patterns are relative to, and that
   * non-anchored patterns are confined beneath. `null` means "match anywhere"
   * (used by the built-in baseline and the global config file).
   */
  root: string | null
  /** Absolute path of the file, or a synthetic label for the baseline/options. */
  path: string
  /** Where the source came from, for logs: "baseline" | "global" | "ancestor" | "nested" | "options". */
  kind: "baseline" | "global" | "ancestor" | "nested" | "options"
}

const REGEX_SPECIAL_CHARS = new Set(".*+?^${}()|[]\\".split(""))

/** Escape a string so it is treated literally inside a regular expression. */
export function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function hasGlob(value: string): boolean {
  return /[*?[\]]/.test(value)
}

/** Convert one path segment (no slashes) to a regex fragment. */
function segmentToRegex(segment: string): string {
  let out = ""
  for (const char of segment) {
    if (char === "*") out += "[^/]*"
    else if (char === "?") out += "[^/]"
    else if (REGEX_SPECIAL_CHARS.has(char)) out += "\\" + char
    else out += char
  }
  return out
}

/**
 * Convert a .ocignore pattern to a regex that matches an absolute path.
 *
 * Supported subset:
 *   - `#` comment lines and blank lines (stripped by `parseOcignore`)
 *   - `!pattern` negation (handled by the caller)
 *   - leading `/` anchors to the source root; otherwise match at any depth below it
 *   - trailing `/` matches a directory and everything beneath it
 *   - `*` matches within a segment, `?` matches one non-slash char, `**` crosses segments
 * Not supported: character classes (`[a-z]`) and backslash escapes.
 *
 * When `root` is `null` the pattern matches anywhere on the filesystem
 * (`(^|/)`); a leading `/` then anchors to the filesystem root.
 */
export function globToRegex(pattern: string, root: string | null): string {
  const anchored = pattern.startsWith("/")
  const dirOnly = pattern.endsWith("/")
  const body = pattern.replace(/^\/+/, "").replace(/\/+$/, "")
  const segments = body.split("/").filter((segment) => segment.length > 0)

  let regex = ""
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!
    if (segment === "**") {
      regex += i === segments.length - 1 ? ".*" : "(.*/)?"
      continue
    }
    regex += segmentToRegex(segment)
    if (i < segments.length - 1) regex += "/"
  }

  let prefix: string
  if (root === null) {
    prefix = anchored ? "^/" : "(^|/)"
  } else {
    prefix = `^${escapeRegex(root)}/`
    // A bare name matches at any depth below the root; a name with a slash or a
    // leading slash is already anchored to the root. Use a capturing group (not
    // `(?:...)`) because Seatbelt's regex dialect is not guaranteed to support
    // non-capturing groups.
    if (!anchored && !body.includes("/")) prefix += "(.*/)?"
  }

  const suffix = dirOnly ? "(/|$)" : "$"
  return prefix + regex + suffix
}

/** Escape a regex for embedding in an SBPL `#"..."` literal. Backslashes are preserved. */
function sbplRegex(regex: string): string {
  return regex.replace(/"/g, '\\"')
}

/** Escape a path for embedding in an SBPL `"..."` string literal. */
function sbplString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
}

/** Parse .ocignore text into raw deny/allow patterns. */
export function parseOcignore(text: string): PatternSet {
  const deny: string[] = []
  const allow: string[] = []
  for (const raw of text.split("\n")) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    if (line.startsWith("!")) {
      const negated = line.slice(1)
      if (negated) allow.push(negated)
    } else {
      deny.push(line)
    }
  }
  return { deny, allow }
}

/** Build a complete SBPL profile from an ordered list of sources (lowest precedence first). */
export function buildProfile(input: {
  sources: readonly PolicySource[]
  protectPolicyFiles?: readonly string[]
}): string {
  const lines = ["(version 1)", "(allow default)"]

  // `file-read*` and `file-write-unlink` are distinct kernel checks. The read
  // rule stops opens, copies, hardlinks and symlink targets (the kernel resolves
  // the real path). The write-unlink rule stops rename(2) and unlink(2) of the
  // protected entry itself, which would otherwise let a denied file be moved to
  // an allowed path and read there. Negations lift both.
  for (const source of input.sources) {
    for (const pattern of source.deny) {
      const regex = sbplRegex(globToRegex(pattern, source.root))
      lines.push(`(deny file-read* (regex #"${regex}"))`)
      lines.push(`(deny file-write-unlink (regex #"${regex}"))`)
    }
  }

  for (const source of input.sources) {
    for (const pattern of source.allow) {
      const regex = sbplRegex(globToRegex(pattern, source.root))
      lines.push(`(allow file-read* (regex #"${regex}"))`)
      lines.push(`(allow file-write-unlink (regex #"${regex}"))`)
    }
  }

  for (const file of input.protectPolicyFiles ?? []) {
    lines.push(`(deny file-write* (literal "${sbplString(file)}"))`)
  }

  return lines.join("\n") + "\n"
}

/** Patterns that could behave surprisingly because Seatbelt rule precedence is not line order. */
export function warnOnGlobNegation(patterns: PatternSet): string[] {
  return patterns.allow.filter(hasGlob)
}

/** The OpenCode config directory that holds the global `.ocignore`. */
export function defaultGlobalDir(env: Record<string, string | undefined> = process.env): string {
  const base = env.XDG_CONFIG_HOME?.trim() || join(homedir(), ".config")
  return join(base, "opencode")
}

/**
 * Canonical absolute path (symlinks resolved). Seatbelt matches the path the
 * kernel resolved, so scoped regexes must be built from canonical roots — on
 * macOS `/tmp` and `/var` are symlinks into `/private`, and a rule anchored to
 * `/var/...` will never match the real `/private/var/...`.
 */
export function canonicalPath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    return resolve(path)
  }
}

/** Every directory from the filesystem root down to `from`, inclusive. */
export function ancestorDirs(from: string): string[] {
  const absolute = resolve(from)
  const parts = absolute.split(sep).filter((part) => part.length > 0)
  const dirs: string[] = [sep]
  let current: string = sep
  for (const part of parts) {
    current = join(current, part)
    dirs.push(current)
  }
  return dirs
}

/** Read one policy file into a scoped source, or return null if it does not exist. */
export function sourceFromFile(path: string, root: string | null, kind: PolicySource["kind"] = "ancestor"): PolicySource | null {
  let text: string
  try {
    text = readFileSync(path, "utf8")
  } catch {
    return null
  }
  const patterns = parseOcignore(text)
  return { root, path, kind, deny: patterns.deny, allow: patterns.allow }
}

export interface PolicyDiscoveryInput {
  /** Directory OpenCode was started in (the session directory). */
  sessionDir: string
  /** The detected project root. */
  projectDir: string
  /** OpenCode config directory holding the global policy file. */
  globalDir: string
  /** Policy file name searched in each directory. Default: ".ocignore". */
  file?: string
  /** Include the built-in secret baseline. Default: true. */
  baseline?: boolean
  /** Look at the global file, ancestors, and (optionally) nested files. Default: true. */
  discover?: boolean
  /** Scan subdirectories for nested policy files. Default: true. */
  subdirectories?: boolean
  /** Directory names skipped while scanning downward. */
  skip?: readonly string[]
  /** Safety cap on discovered files. Default: 256. */
  maxFiles?: number
  /** Highest-precedence extra deny patterns from plugin options. */
  extra?: readonly string[]
  /** Highest-precedence extra allow patterns from plugin options. */
  allow?: readonly string[]
}

export interface PolicyDiscoveryResult {
  /** Ordered lowest-precedence first. */
  sources: PolicySource[]
  /** Absolute paths of every discovered policy file. */
  files: string[]
}

/**
 * Discover the policy files that apply to a session, lowest precedence first:
 *
 *   1. built-in baseline (matches anywhere)
 *   2. global file in the OpenCode config dir (matches anywhere)
 *   3. `.ocignore` in every ancestor of the session dir, root -> closest
 *   4. the project root file, if it is not already an ancestor
 *   5. nested `.ocignore` files in subdirectories (shallow -> deep)
 *   6. explicit plugin options (highest precedence)
 *
 * Denies are unioned, so a closer file can only add protection. Each file's
 * patterns are scoped to that file's own directory.
 */
export function discoverPolicy(input: PolicyDiscoveryInput): PolicyDiscoveryResult {
  const name = input.file && input.file.trim() ? input.file.trim() : DEFAULT_POLICY_FILE
  if (name.includes("/")) {
    throw new Error(`policy file name must not contain "/": ${name}`)
  }
  const sessionDir = canonicalPath(input.sessionDir)
  const projectDir = canonicalPath(input.projectDir)
  const globalDir = canonicalPath(input.globalDir)
  const sky = new Set(input.skip ?? DEFAULT_SKIP_DIRECTORIES)
  const maxFiles = input.maxFiles && input.maxFiles > 0 ? input.maxFiles : 256

  const sources: PolicySource[] = []
  const files: string[] = []
  const seen = new Set<string>()

  const add = (path: string, root: string | null, kind: PolicySource["kind"]): boolean => {
    if (files.length >= maxFiles) return false
    if (seen.has(path)) return false
    const source = sourceFromFile(path, root, kind)
    if (!source) return false
    seen.add(path)
    sources.push(source)
    files.push(path)
    return true
  }

  if (input.baseline !== false) {
    sources.push({ root: null, path: "<baseline>", kind: "baseline", deny: [...BASELINE_DENY], allow: [...BASELINE_ALLOW] })
  }

  if (input.discover !== false) {
    add(join(globalDir, name), null, "global")

    for (const dir of ancestorDirs(sessionDir)) {
      if (dir === globalDir) continue
      add(join(dir, name), dir, "ancestor")
    }

    // The project root is normally an ancestor of the session dir; add it if not.
    add(join(projectDir, name), projectDir, "ancestor")

    if (input.subdirectories !== false && files.length < maxFiles) {
      const dirs: string[] = []
      const walk = (dir: string, depth: number) => {
        if (depth > 16) return
        let entries
        try {
          entries = readdirSync(dir, { withFileTypes: true })
        } catch {
          return
        }
        for (const entry of entries) {
          if (!entry.isDirectory() || sky.has(entry.name)) continue
          const child = join(dir, entry.name)
          dirs.push(child)
          walk(child, depth + 1)
        }
      }
      walk(projectDir, 0)
      dirs.sort((a, b) => depthOf(a) - depthOf(b) || a.localeCompare(b))
      for (const dir of dirs) {
        if (files.length >= maxFiles) break
        add(join(dir, name), dir, "nested")
      }
    }
  } else {
    // Discovery disabled: only the project root file.
    add(join(projectDir, name), projectDir, "ancestor")
  }

  if ((input.extra?.length ?? 0) > 0 || (input.allow?.length ?? 0) > 0) {
    sources.push({
      root: projectDir,
      path: "<options>",
      kind: "options",
      deny: [...(input.extra ?? [])],
      allow: [...(input.allow ?? [])],
    })
  }

  return { sources, files }
}

function depthOf(value: string): number {
  return value.split(sep).filter((part) => part.length > 0).length
}
