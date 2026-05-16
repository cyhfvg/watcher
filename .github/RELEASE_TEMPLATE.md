# Release {{ version }}

## Changes

{{ changelog }}

## Build Targets

- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-gnu`

## Assets

- `watcher-{{ version }}-x86_64-unknown-linux-musl.tar.gz`
- `watcher-{{ version }}-x86_64-pc-windows-gnu.zip`

## Notes

- Tag format must be `v*`, for example `v0.1.0`.
- Release artifacts are published automatically by GitHub Actions after the tag is pushed.
