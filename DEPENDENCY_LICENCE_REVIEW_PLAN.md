# Dependency and licence review plan

This is planning-only. No dependencies have been installed or downloaded.

Before implementation, record the exact version, source URL, archive size,
SHA-256, licence, transitive native components, and redistribution obligations
for each candidate:

| Area | Candidate family | Review gate |
|---|---|---|
| Desktop shell | Tauri and its Rust/Node toolchain | Apache-2.0/MIT compatibility and offline packaging |
| Scanner access | SANE, TWAIN/WIA, eSCL/AirScan | platform-specific licences and device privacy |
| Image processing | Rust-native crate or libvips/ImageMagick | codec patents, LGPL/GPL boundaries, bundled DLLs |
| PDF | printpdf/lopdf or equivalent | licence and font/embed obligations |
| OCR | offline engine abstraction | model/data licence, language packs, native runtime |
| Frontend | React or Svelte/TypeScript | dependency notices and lockfile reproducibility |

The first milestone should use a mock scanner and sanitized fixtures so that
the UI, session format, export flow, and recovery logic can be tested without
hardware, network access, or private documents.

2026-08-20 research update: NAPS2 is the closest workflow reference, but its
GPL/LGPL/.NET stack is not the intended base. Prioritize Windows WIA and direct
eSCL/WSD network scanning; defer TWAIN, SANE, macOS, OCR, PDFium, and large
image runtimes behind capability and license gates. See
`RESEARCH_2026_08_20_SCANNER_ECOSYSTEM.md`.
