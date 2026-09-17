# Built-in scanner backend plan

Date: 2026-09-09  
Status: offline architecture milestone; no scanner or network I/O performed

## Goal

Move Just Scanner toward driver-light operation without representing unfinished
protocol work as scanner support. A scanner model name, USB identifier, or user
permission must never be enough on its own to activate an unimplemented backend.

## Backend order

1. **Mock fixture** — current offline-tested scan and export path.
2. **Windows WIA 2.0** — first local-device bridge. It depends on an installed
   Windows/vendor driver. The production seam currently performs explicit,
   privacy-sanitized discovery only; connection, item-tree mapping, property
   read/write/readback, and transfer are not yet implemented.
3. **WSD Scan** — first planned in-app network transport. The protocol has a
   public Microsoft/PWG contract. No discovery, HTTP/SOAP exchange, or device
   request is implemented yet.
4. **eSCL/AirScan** — possible later in-app network transport. Keep it
   research-only until the project has a satisfactory specification and licence
   basis. Do not copy GPL backend code into this project without an explicit
   project-licensing decision.
5. **Native USB profiles** — device-family-specific fallback, not a generic
   scanner driver. Keep disabled until a clean-room profile, bounded parser,
   transfer state machine, cancellation behavior, and sanitized fixture captures
   exist for an explicitly authorised device.

The central registry in `src/scanner_backend_policy.*` records which transport
is built into the app, whether an external driver is required, its maturity, and
the operations presently supported. Permission cannot promote a planned or
research-only backend into a working backend.

## Candidate device categories

| Device category | First path | Driver-free fallback |
| --- | --- | --- |
| Local WIA-capable flatbed | WIA 2.0 through its installed driver | Native USB profile only after clean-room approval |
| Local legacy scanner | WIA/TWAIN availability assessment after connection | Native USB profile only after clean-room approval |
| Network WSD scanner | Direct WSD Scan | eSCL only after specification/licence review |

## Clean-room native USB boundary

Do not execute VueScan, capture its traffic, attach a filter driver, enumerate a
scanner, or power/use hardware as part of offline development. Before any future
capture session:

- tell the user exactly which scanner and action will be tested and obtain the
  applicable local-device or network-test authorization;
- use only synthetic targets or sanitized test documents;
- review the capture method and applicable licence/interoperability constraints;
- record observations as an independently written protocol description, not
  copied executable content, strings, tables, code, or distinctive UI;
- redact serial numbers, network addresses, paths, and document data from all
  fixtures, logs, screenshots, packages, and AI-visible output;
- begin with enumeration and one bounded operation, then stop and review the
  evidence before expanding scope;
- retain timeouts, maximum lengths, response validation, cancellation, and an
  emergency stop path from the first live prototype.

## Next implementation milestones

1. Complete the WIA `CreateDevice` and item-tree adapter behind the existing MTA
   worker, using injected hardware-free fixtures first.
2. Add WIA property mapping and strict readback validation, then an injected
   `IWiaTransfer` stream adapter. Do not activate it on hardware merely because
   offline tests pass.
3. Complete the hardware-free DPWS metadata model needed to identify a
   `ScanDeviceType` responder and locate its hosted scan service without logging
   addresses or identifiers. Bounded description, configuration, status, and
   SOAP-fault parsing is complete using sanitized fixtures.
4. After separate metadata-test authorization, perform one bounded WSD
   metadata-only check without logging a device identifier.
5. Consider native USB only when WIA/WSD cannot meet a specific device goal.

## Evidence boundary

This plan and its tests establish routing and safety policy only. They do not
establish local WIA, legacy-scanner, network WSD, eSCL, or native USB
compatibility.
