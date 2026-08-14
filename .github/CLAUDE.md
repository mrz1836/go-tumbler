# CLAUDE.md

## 🤖 Welcome, Claude

This repository uses **`AGENTS.md`** as the single source of truth for:

* Coding conventions (naming, formatting, commenting, testing)
* Contribution workflows (branch prefixes, commit message style, PR templates)
* Release, CI, and dependency‑management policies
* Security reporting and governance links

> **TL;DR:** **Read [`AGENTS.md`](AGENTS.md) first.**
> All technical or procedural questions are answered there.

### Quick Checklist for Claude

1. **Study [`AGENTS.md`](AGENTS.md)**
   Make sure every automated change or suggestion respects those rules.
2. **Respect the security model**
   [`SECURITY.md`](../SECURITY.md) defines the threat model, cryptographic
   primitives, and the honest limits of this module. All changes to the
   crypto core, wire format, or secret handling must align with it.
3. **Follow branch‑prefix and commit‑message standards**
   They drive auto‑labeling and CI gates.
4. **Never tag releases**
5. **Pass CI**
   Run `gofmt`, `goimports`, `go vet`, `staticcheck`, and `golangci‑lint`
   locally before opening a PR — and keep the build `CGO_ENABLED=0`.

If you encounter conflicting guidance elsewhere, `AGENTS.md` wins.
Questions or ambiguities? Open a discussion or ping a maintainer instead of guessing.

Happy hacking!
