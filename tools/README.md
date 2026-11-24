# Dev Tools

This directory holds platform-specific binaries used only for development.
Nothing here is shipped in the production Go binary.

Tool versions are pinned. Generated files are committed, and CI regenerates
the `sqlc` and `templ` output with the pinned versions and rejects a commit
whose generated code differs. Use exactly these versions and bump them
deliberately (here, in the `Makefile` and in `.github/workflows/ci.yml` at the
same time).

| Tool | Version |
|---|---|
| `tailwindcss` (standalone) | v4.2.2 |
| `templ` | v0.3.1001 |
| `sqlc` | v1.30.0 |

## `tailwindcss` (standalone, no Node required)

Download the matching binary for your platform from the v4.2.2 release (the
version the committed `app.css` was built with):
https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.2.2

- Windows (x64): `tailwindcss-windows-x64.exe` → save as `tools/tailwindcss.exe`
- macOS (arm64): `tailwindcss-macos-arm64` → save as `tools/tailwindcss`
- Linux (x64):   `tailwindcss-linux-x64`   → save as `tools/tailwindcss`

Compare the download with the `sha256sums.txt` published in the same release
before you run it. Make the binary executable:

```bash
chmod +x tools/tailwindcss
```

Then regenerate CSS with `make tailwind-gen`. The compiled output lives at
`internal/server/frontend/web/static/app.css` and is committed so production
builds don't need Tailwind.

## `templ` and `sqlc`

Install the pinned versions (Go tools, go-install style):

```bash
make tools
# or:
go install github.com/a-h/templ/cmd/templ@v0.3.1001
go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0
```

Regenerate templates with `make templ-gen` and database code with
`make sqlc-gen`. The generated `*_templ.go` and `sqlcgen` files are committed.
