// Root entry so the package also works when loaded by directory path
// (e.g. `plugins: ["./path/to/opencode-seatbelt"]`). npm consumers use the
// `exports` map in package.json, which points at the same module.
export { default } from "./src/index.ts"
