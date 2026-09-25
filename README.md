# opencode-seatbelt <a href="https://www.npmjs.com/package/opencode-seatbelt"><img alt="npm" src="https://img.shields.io/npm/v/opencode-seatbelt?logo=npm&color=cb3837" align="right"></a>

**A real kernel sandbox for OpenCode on macOS, driven by `.ocignore`.**

`opencode-seatbelt` applies a macOS [Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
profile to the OpenCode process the moment the plugin loads. From then on, **every tool and
every child process** is confined by the kernel: the `read` tool, `glob`, `grep`, the shell, an
MCP server, a custom tool nobody has heard of — all of them reduce to the same `open()`/`read()`
syscalls, and the kernel answers for all of them.

That is the difference between this and a filter plugin. A `tool.execute.before` hook matches
command text, so it can be defeated by `tail` instead of `cat`, a symlink, a hardlink, a glob, a
`$(...)`, an interpreter, base64, or a path computed at runtime. A Seatbelt profile is not matched
against commands at all — it is enforced on the file, at the moment it is opened.

```
before:  cat .env        -> API_KEY=super-secret
after:   cat .env        -> Operation not permitted      (kernel)
         tail .env       -> Operation not permitted
         cat symlink.env -> Operation not permitted      (realpath resolved by the kernel)
         mv .env /tmp/x  -> Operation not permitted      (cannot be laundered out)
         base64 .env     -> Operation not permitted
         python -c ...   -> Operation not permitted
```

## Requirements

- macOS (Seatbelt is a macOS facility; Linux/Landlock is not implemented yet)
- OpenCode v2 (plugin API `@opencode/plugin` `^2.0.16`)

## Install

```sh
opencode plugin add opencode-seatbelt
```

Or add it to `opencode.json(c)` yourself:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["opencode-seatbelt"]
}
```

A project-local `opencode.json` protects that project; a global install protects every project.
After the first launch, create a `.ocignore` in the repositories you care about.

## Quick start

Create `.ocignore` in your project root:

```gitignore
# Never let the agent read these.
.env
.env.*
secrets/
*.pem
*.key
config/credentials.json

# ...except this one, it's a template.
!.env.example
```

The built-in baseline already covers common secret shapes (`.env`, `id_rsa`, `*.pem`, `*.key`,
`.ssh/`, `.aws/`, `.npmrc`, `.git-credentials`, `credentials.json`, …), so a `.ocignore` is for
project-specific additions.

## How it works

At `setup`, the plugin:

1. discovers every `.ocignore` that applies to the session (see
   [Which `.ocignore` files apply](#which-ocignore-files-apply)) and merges them with the built-in baseline,
2. compiles each pattern to a Seatbelt regex (not to a list of existing files, so files created
   later are still covered),
3. calls `sandbox_init` from `/usr/lib/libsandbox.dylib` on the OpenCode process — the same call
   `sandbox-exec` makes before `exec`.

Each denied pattern is enforced against two kernel checks: `file-read*`, which stops opens,
copies, hardlinks and symlinked reads (the kernel resolves the real path), and
`file-write-unlink`, which stops `rename`/`unlink` of the protected entry itself. Without the
second rule a denied file could be renamed into an allowed directory and read there.

Because the confinement is process-wide, the profile is applied **once** and cannot be changed
afterwards. See [Changing the policy](#changing-the-policy).

## Which `.ocignore` files apply

The plugin collects every policy file that applies to the session and unions them, lowest
precedence first:

1. the built-in baseline (matches anywhere),
2. the global file `~/.config/opencode/.ocignore` (matches anywhere),
3. every `.ocignore` in an ancestor of the session directory, from the filesystem root down,
4. the project root file,
5. nested `.ocignore` files found by scanning subdirectories (skipping `node_modules`, `.git`,
   `dist`, and similar build/vendor directories).

Each file's patterns are **scoped to the directory that contains it**, like gitignore: `secrets/`
in `packages/web/.ocignore` protects `packages/web/secrets/`, and a bare `goozoo` matches at any
depth *below that directory*. Only the global file and the baseline match anywhere on the
filesystem.

Denies are **unioned**, so a closer file can only add protection — it can never loosen an
ancestor's deny. Use `!pattern` to re-allow something explicitly.

This mirrors how `opencode.json` is discovered (global + cwd → filesystem root), plus nested files
so monorepos work. Run `bun run e2e` to see exactly which files were picked up and in what order.

## `.ocignore` syntax

A deliberately small subset of gitignore. It is compiled to Seatbelt rules, so the semantics are
documented here rather than inherited wholesale:

| Syntax | Meaning |
| --- | --- |
| `# comment` | ignored |
| `*.env` | match at any depth below the file's own directory |
| `/secrets.txt` | leading `/` anchors to the file's own directory (the filesystem root for the global file) |
| `secrets/` | trailing `/` matches the directory and everything beneath it |
| `*` | matches within a path segment (does not cross `/`) |
| `?` | matches one non-`/` character |
| `**` | crosses path segments (`a/**/b`, `**/*.pem`) |
| `!keep.txt` | re-allow a path the rules would otherwise deny |

Not supported: character classes (`[a-z]`) and backslash escapes.

> **Negation and precedence.** A negation lifts *both* rules for the path (read and
> rename/unlink). Negations become `allow` rules emitted after every `deny`, so a literal
> negation wins over a matching deny (verified, including baseline exceptions such as
> `.env.example`). A negation that itself contains a glob may be ranked by Seatbelt's rule
> specificity rather than by position — the plugin warns when it sees one. Keep negations precise.

## Options

```jsonc
{
  "plugins": [
    {
      "package": "opencode-seatbelt",
      "options": {
        "file": ".ocignore",
        "baseline": true,
        "discover": true,
        "subdirectories": true,
        "extraPatterns": ["*.token"],
        "allowPatterns": ["public.env"],
        "mode": "enforce",
        "protectPolicyFile": true,
        "log": true
      }
    }
  ]
}
```

| Option | Default | Description |
| --- | --- | --- |
| `file` | `".ocignore"` | Policy file name searched in each directory. |
| `baseline` | `true` | Include the built-in secret baseline. |
| `discover` | `true` | Look for the global file, ancestor files, and nested files. `false` restricts to the project root. |
| `subdirectories` | `true` | Recursively scan subdirectories for nested `.ocignore` files. |
| `skipDirectories` | build/vendor dirs | Directory names skipped while scanning down (`node_modules`, `.git`, `dist`, …). |
| `maxFiles` | `256` | Safety cap on the number of discovered policy files. |
| `extraPatterns` | `[]` | Additional deny patterns, highest precedence. |
| `allowPatterns` | `[]` | Additional allow (negation) patterns. |
| `mode` | `"enforce"` | `"warn"` prints the compiled profile and does not sandbox — useful to preview. |
| `protectPolicyFile` | `true` | Deny writes to every discovered policy file so the agent cannot pre-edit it for the next launch. |
| `log` | `true` | Print sandbox status lines. |

## Changing the policy

`sandbox_init` can only be called once. A second call on an already-sandboxed process fails, in
either direction — you cannot tighten it and you cannot relax it. Practically:

- Adding or removing a `.ocignore` entry requires an **OpenCode restart** before it takes effect.
- Removing an entry mid-session does **not** un-block it; the process stays confined until it exits.
- Restart the background service (`opencode service restart`) or your running session.

This is the price of a kernel boundary. There is no mutable policy at the syscall layer.

## Caveats

- **macOS only.** Windows has no Seatbelt; Linux would use Landlock/seccomp/bubblewrap — a
  different mechanism, not yet implemented.
- **The baseline can over-block.** `*.key` will hide a development TLS key from the agent too.
  If that bites, set `baseline: false` and list exactly what you want in `.ocignore`.
- **A containing directory can still be moved.** The policy blocks `rename`/`unlink` of a
  protected entry, but not of an *ancestor* directory that merely contains it (`mv config /tmp/`
  launders `config/x`). Closing that fully would mean forbidding directory renames under the
  project, which breaks normal refactors, so it is left to you: keep secrets somewhere the agent
  has no reason to move, and treat a writable project as untrusted.
- **One profile per process.** A long-lived server that opens several projects applies the
  `.ocignore` from the first project it loads. Restart per project, or configure global patterns.
- **`sandbox_init` is a private, deprecated API.** It is not a supported Apple contract and could
  change in a future macOS release. Re-test after major upgrades.
- **It does not control the network.** `(allow default)` still permits outbound connections, so a
  file the sandbox allows can still be sent somewhere. Add network rules if you need egress control.
- **It is not a redaction layer.** Whatever the sandbox permits still reaches the model provider.

## Development

```sh
bun install
bun test          # unit tests for discovery + the .ocignore compiler
bun run typecheck
bun run e2e       # applies a real profile to a throwaway process and verifies it
                  # (run in a plain terminal, not inside an OpenCode session)
```

CI runs everything — typecheck, unit tests, and the kernel-boundary `e2e` suite — on macOS for
every pull request and push to `master` (`.github/workflows/test.yml`), so it tests in the same
environment OpenCode users run on.

## License

MIT
