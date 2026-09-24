import { afterAll, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  ancestorDirs,
  buildProfile,
  defaultGlobalDir,
  discoverPolicy,
  globToRegex,
  parseOcignore,
  warnOnGlobNegation,
  type PolicySource,
} from "../src/policy.ts"

const R = "/project"

describe("globToRegex — scoped to a directory", () => {
  test("bare name matches at any depth below the root", () => {
    expect(globToRegex(".env", R)).toBe("^/project/(.*/)?\\.env$")
  })

  test("* stays within a path segment", () => {
    expect(globToRegex("*.env", R)).toBe("^/project/(.*/)?[^/]*\\.env$")
  })

  test("leading slash anchors to the source root", () => {
    expect(globToRegex("/.env", R)).toBe("^/project/\\.env$")
  })

  test("a pattern containing a slash is anchored to the source root", () => {
    expect(globToRegex("sub/x", R)).toBe("^/project/sub/x$")
  })

  test("trailing slash matches a directory and its contents", () => {
    expect(globToRegex("secrets/", R)).toBe("^/project/(.*/)?secrets(/|$)")
  })

  test("** crosses segments including zero", () => {
    expect(globToRegex("**/*.pem", R)).toBe("^/project/(.*/)?[^/]*\\.pem$")
    expect(globToRegex("a/**/b", R)).toBe("^/project/a/(.*/)?b$")
    expect(globToRegex("a/**", R)).toBe("^/project/a/.*$")
  })

  test("? matches one non-slash character", () => {
    expect(globToRegex("token.?", R)).toBe("^/project/(.*/)?token\\.[^/]$")
  })

  test("regex metacharacters in the root are escaped", () => {
    expect(globToRegex("/.env", "/a.b+c")).toBe("^/a\\.b\\+c/\\.env$")
  })

  test("patterns scoped to different roots do not leak into each other", () => {
    expect(globToRegex("goozoo", "/repo")).not.toContain("/repo/pkg")
    expect(globToRegex("goozoo", "/repo/pkg")).toContain("^/repo/pkg/")
  })
})

describe("globToRegex — global (match anywhere)", () => {
  test("bare name matches anywhere", () => {
    expect(globToRegex(".env", null)).toBe("(^|/)\\.env$")
  })

  test("leading slash anchors to the filesystem root", () => {
    expect(globToRegex("/etc/passwd", null)).toBe("^/etc/passwd$")
  })

  test("directory patterns match at any depth", () => {
    expect(globToRegex(".ssh/", null)).toBe("(^|/)\\.ssh(/|$)")
  })
})

describe("parseOcignore", () => {
  test("strips comments and blanks, splits negations", () => {
    const parsed = parseOcignore(`
      # a comment

      .env
      secrets/
      !keep.env
    `)
    expect(parsed.deny).toEqual([".env", "secrets/"])
    expect(parsed.allow).toEqual(["keep.env"])
  })

  test("ignores a bare ! with no pattern", () => {
    const parsed = parseOcignore("!\n!keep.env\n")
    expect(parsed.allow).toEqual(["keep.env"])
  })
})

describe("buildProfile", () => {
  const sources: PolicySource[] = [
    { root: null, path: "<baseline>", kind: "baseline", deny: ["*.env"], allow: [".env.example"] },
    { root: R, path: `${R}/.ocignore`, kind: "ancestor", deny: [".env", "*.secret"], allow: ["keep.env", "*.sample"] },
  ]
  const profile = buildProfile({ sources, protectPolicyFiles: [`${R}/.ocignore`] })

  test("emits a deny regex per pattern for reads and renames, scoped to each source root", () => {
    expect(profile).toContain(`(deny file-read* (regex #"(^|/)[^/]*\\.env$"))`)
    expect(profile).toContain(`(deny file-write-unlink (regex #"(^|/)[^/]*\\.env$"))`)
    expect(profile).toContain(`(deny file-read* (regex #"^/project/(.*/)?\\.env$"))`)
    expect(profile).toContain(`(deny file-write-unlink (regex #"^/project/(.*/)?\\.env$"))`)
    expect(profile).toContain(`(deny file-read* (regex #"^/project/(.*/)?[^/]*\\.secret$"))`)
    expect(profile).toContain(`(deny file-write-unlink (regex #"^/project/(.*/)?[^/]*\\.secret$"))`)
  })

  test("every deny also blocks rename/unlink, and negations lift both", () => {
    const reads = profile.match(/\(deny file-read\*/g)?.length ?? 0
    const unlinks = profile.match(/\(deny file-write-unlink/g)?.length ?? 0
    expect(unlinks).toBe(reads)
    expect(profile).toContain(`(allow file-read* (regex #"(^|/)\\.env\\.example$"))`)
    expect(profile).toContain(`(allow file-write-unlink (regex #"(^|/)\\.env\\.example$"))`)
    expect(profile).toContain(`(allow file-read* (regex #"^/project/(.*/)?keep\\.env$"))`)
    expect(profile).toContain(`(allow file-write-unlink (regex #"^/project/(.*/)?keep\\.env$"))`)
  })

  test("emits allow regexes for negations", () => {
    expect(profile).toContain(`(allow file-read* (regex #"(^|/)\\.env\\.example$"))`)
    expect(profile).toContain(`(allow file-read* (regex #"^/project/(.*/)?keep\\.env$"))`)
    expect(profile).toContain(`(allow file-read* (regex #"^/project/(.*/)?[^/]*\\.sample$"))`)
  })

  test("protects every discovered policy file from writes", () => {
    expect(profile).toContain(`(deny file-write* (literal "${R}/.ocignore"))`)
  })

  test("profile starts with an allow-default preamble", () => {
    expect(profile.startsWith("(version 1)\n(allow default)\n")).toBe(true)
  })

  test("warnOnGlobNegation flags only glob negations", () => {
    expect(warnOnGlobNegation({ deny: [], allow: ["keep.env", "*.sample"] })).toEqual(["*.sample"])
  })
})

describe("ancestorDirs", () => {
  test("returns root first and the target last", () => {
    expect(ancestorDirs("/a/b")).toEqual(["/", "/a", "/a/b"])
  })

  test("handles the root itself", () => {
    expect(ancestorDirs("/")).toEqual(["/"])
  })
})

describe("defaultGlobalDir", () => {
  test("uses XDG_CONFIG_HOME when set", () => {
    expect(defaultGlobalDir({ XDG_CONFIG_HOME: "/xdg" })).toBe("/xdg/opencode")
  })

  test("falls back to ~/.config/opencode", () => {
    expect(defaultGlobalDir({})).toMatch(/\/\.config\/opencode$/)
  })
})

describe("discoverPolicy", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "ocignore-")))
  const globalDir = join(base, "home", ".config", "opencode")
  const repo = join(base, "repo")
  const pkg = join(repo, "pkg")
  const deep = join(repo, "sub", "deep")
  const skipped = join(pkg, "node_modules")

  mkdirSync(globalDir, { recursive: true })
  mkdirSync(deep, { recursive: true })
  mkdirSync(skipped, { recursive: true })
  writeFileSync(join(globalDir, ".ocignore"), "*.token\n")
  writeFileSync(join(repo, ".ocignore"), "goozoo\n")
  writeFileSync(join(pkg, ".ocignore"), "pkgsecret\n")
  writeFileSync(join(deep, ".ocignore"), "deepsecret\n")
  writeFileSync(join(skipped, ".ocignore"), "shouldnotload\n")

  test("collects baseline, global, ancestors, and nested files in order", () => {
    const result = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir })
    expect(result.sources.map((s) => s.kind)).toEqual([
      "baseline",
      "global",
      "ancestor", // repo (project root)
      "ancestor", // pkg (session dir); also the project root is skipped as seen
      "nested", // sub/deep
    ])
    const paths = result.files
    expect(paths).toContain(join(globalDir, ".ocignore"))
    expect(paths).toContain(join(repo, ".ocignore"))
    expect(paths).toContain(join(pkg, ".ocignore"))
    expect(paths).toContain(join(deep, ".ocignore"))
    expect(paths).not.toContain(join(skipped, ".ocignore"))
  })

  test("scopes each file to its own directory", () => {
    const result = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir })
    const nested = result.sources.find((s) => s.path === join(deep, ".ocignore"))!
    expect(nested.root).toBe(deep)
    const global = result.sources.find((s) => s.kind === "global")!
    expect(global.root).toBe(null)
    const repoSource = result.sources.find((s) => s.path === join(repo, ".ocignore"))!
    expect(repoSource.root).toBe(repo)
  })

  test("baseline can be disabled", () => {
    const result = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir, baseline: false })
    expect(result.sources.some((s) => s.kind === "baseline")).toBe(false)
  })

  test("subdirectories: false skips nested files", () => {
    const result = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir, subdirectories: false })
    expect(result.files).not.toContain(join(deep, ".ocignore"))
  })

  test("discover: false reads only the project root file", () => {
    const result = discoverPolicy({ sessionDir: pkg, projectDir: repo, globalDir, discover: false })
    expect(result.files).toEqual([join(repo, ".ocignore")])
  })

  test("plugin options are the highest-precedence source", () => {
    const result = discoverPolicy({
      sessionDir: pkg,
      projectDir: repo,
      globalDir,
      extra: ["*.token"],
      allow: ["public.env"],
    })
    const last = result.sources.at(-1)!
    expect(last.kind).toBe("options")
    expect(last.deny).toEqual(["*.token"])
    expect(last.allow).toEqual(["public.env"])
    expect(last.root).toBe(repo)
  })

  test("canonicalizes roots so scoped rules match the path the kernel resolves", () => {
    const real = join(base, "real")
    const link = join(base, "link")
    mkdirSync(join(real, "pkg"), { recursive: true })
    symlinkSync(real, link)
    writeFileSync(join(real, ".ocignore"), "goozoo\n")

    const result = discoverPolicy({ sessionDir: join(link, "pkg"), projectDir: link, globalDir: join(base, "none") })
    const source = result.sources.find((s) => s.deny.includes("goozoo"))!
    expect(source.root).toBe(real)
    expect(source.root).not.toContain("/link")
  })

  afterAll(() => rmSync(base, { recursive: true, force: true }))
})
