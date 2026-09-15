# Just Scanner Win

Windows-first scanner utility under clean-room development. **Use at your own risk.**

Latest saved state: `RESUME_2026_09_10_DPWS_DISCOVERY_OFFLINE.md`.

The authorized direct WSD validation is recorded in
`LIVE_BROTHER_WSD_SCAN_2026_09_09.md`. It confirmed the Brother MFC-J6530DW,
queried its capabilities/status, and retrieved one flatbed plus two ADF pages
without a vendor scanner driver. Private outputs remain excluded from source.

Just Scanner is a Windows-first scanner utility under clean-room development.
The current GUI remains a dependency-free native mock/session application. A
separate authorization-gated diagnostic harness has now live-validated direct
WSD scanning on a Brother MFC-J6530DW; that network transport is not yet wired
into the GUI. No external library, OCR engine, or vendor scanner driver was used.

## Current verified scope

- language-neutral scanner capability and request contract;
- deterministic mock scanner backed by synthetic PGM fixtures;
- non-destructive page sessions with reorder, rotate, crop, brightness,
  contrast, exclude, and rescan operations;
- bounded, versioned session persistence and recovery from a saved backup;
- ordered collision-safe PGM export, Windows-native PNG/JPEG/TIFF export, and
  bounded multipage grayscale PDF export;
- Unicode-safe Windows export names, native decode validation, and tested
  50-page session ordering/persistence;
- native C++ tests built with the already-installed MSVC toolchain.
- hardware-free WIA capability, transfer, and worker-lifecycle models covering flatbed,
  feeder, duplex, privacy-preserving discovery, property coercion,
  single-operation serialization, cancellation, safe shutdown, jams, and transfer limits.
- a dedicated MTA worker-thread queue with value-only requests/replies, injected
  backend and COM-apartment seams, sanitized backend failures, cancellation, and
  shutdown tests;
- a dormant production WIA 2.0 backend that creates `IWiaDevMgr2` only when the
  worker opens it and supports explicit local-scanner refresh with bounded,
  privacy-sanitized discovery. Tests construct but never open this backend.
- a fail-closed backend policy registry covering mock, WIA 2.0, WSD, eSCL, and
  native USB routes. Only implemented operations can be enabled; permission by
  itself cannot activate a planned or research-only transport.
- hardware-free WSD Scan request/job models for scanner information, ticket
  validation, job creation, image retrieval, cancellation, credential matching,
  state ordering, and bounded image transfer. They perform no network I/O.
- a Windows XmlLite-based, namespace-aware WSD `GetScannerElements` SOAP codec
  tested only with a sanitized response fixture. It blocks DTDs/entities and
  applies XML depth, payload, identifier, field, and requested-element bounds.
- bounded WSD configuration, status, and SOAP-fault decoding from sanitized
  fixtures. It preserves vendor-extended states, rejects malformed/duplicate
  capabilities and reasons, and marks only documented temporary faults retryable.
- a hardware-free native DPWS discovery and metadata model with an injected
  exchange seam, correlated WS-Discovery and WS-Transfer responses, source-bound
  IPv4 transport validation, opaque public scanner IDs, stale-selection checks,
  cancellation, bounded parsing, and sanitized fixtures. No production network
  transport is connected to this model.
- a bounded native WinHTTP POST executor behind an injectable transport seam.
  It uses no proxy and rejects redirects, non-success responses, unexpected
  content types, unsafe endpoints, cancellation, and oversized bodies. Its
  offline tests use a fake executor; it is not connected to discovery or GUI.
- a bounded, privacy-preserving PowerShell WSD diagnostic harness that has
  identified and directly scanned the authorized Brother MFC-J6530DW using its
  live DPWS namespace profile; private scan output is ignored and never a test
  fixture or release input.

This is not yet a scanner-compatible release. The native GUI is an offline
mock and has not yet received visible user acceptance. PNG/JPEG/TIFF currently
use Windows Imaging Component and need clean-machine validation; other
platforms remain pending. Independently rendered PDF acceptance is also
pending. Windows WIA remains the first proposed live backend and requires a
separate hardware test gate. Its hardware-free adapter rules are defined in
`docs/WINDOWS_WIA_ADAPTER_CONTRACT.md`. The driver-light routing and clean-room
USB boundary are defined in `docs/BUILT_IN_BACKEND_PLAN_2026_09_09.md`.

## Offline build and test

Run `Build and Test Offline.cmd`. It invokes the already-installed MSVC
compiler directly, builds only the checked-in source, and uses no package
manager or network operation. `CMakeLists.txt` is retained for a future
complete CMake generator environment.

## Offline mock interface

The build creates `build-native\just_scanner_app.exe`, a native Windows mock
workspace. Its interface scales up to 115 percent when the monitor work area
fits it and scales down only as needed to stay on-screen vertically. It
provides Photo, Flatbed Document, and mock ADF modes; DPI choice; a separate
synthetic pre-scan; drag-to-select crop; non-destructive scan/session pages;
rotation and include/exclude; an output-folder picker; and PDF or JPG output.
PDF saves all included pages as one document. JPG saves each included page as
a separate file in the selected folder. ADF defaults to multipage PDF, while
the user may explicitly choose the separate-JPG folder workflow. It uses only
the sanitized PGM fixtures and does not open the production WIA backend.

Run `build-native\just_scanner_app.exe --self-check` for a no-window offline
startup check. Launching without that argument opens the visible interface.

## Boundaries

The dependency licence decision is still open. No code, assets, schemas, or
distinctive UI were copied from VueScan, NAPS2, ScanTailor Advanced,
ScanExact/iCopy, sane-airscan, vendor software, or scanner SDKs. See
`docs/CLEAN_ROOM_AND_SCOPE.md` before extending the project.
