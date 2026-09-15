# Windows WIA adapter contract v1

Status: hardware-free design plus pure C++ capability, discovery, and transfer
models. No WIA COM interface, device enumeration, connection, property write,
transfer, or scanner action has been performed.

## Goals

1. Enumerate installed WIA 2.0 scanner devices only after an explicit user
   refresh action.
2. Map each selected device's actual item tree and property constraints into
   the existing backend-neutral capability contract.
3. Support flatbed preview/scan first, then feeder simplex, then duplex only
   when the driver reports the corresponding items and properties.
4. Transfer into a bounded staged master, validate it, and atomically publish
   it without overwriting an existing original.
5. Keep device identifiers, serial-like values, paths, and image data out of
   logs and user-facing errors.

## COM and threading boundary

The WIA adapter runs on one dedicated Windows worker thread with an explicitly
initialized COM apartment. COM interface pointers never cross threads. UI and
session code communicate with it through value-only requests, progress events,
cancellation tokens, and sanitized results. Shutdown cancels or completes the
active operation before releasing the item tree and device manager.

## Discovery and connection

1. Create `IWiaDevMgr2` only inside the worker.
2. On explicit refresh, call `EnumDeviceInfo` and retain scanner-class entries.
3. Read only the minimum display name, manufacturer and WIA device identifier.
4. Expose an opaque per-refresh identifier to the UI. Do not persist or log the
   raw WIA device identifier.
5. Connect only after selection by calling `CreateDevice`, which returns the
   root `IWiaItem2` tree.
6. Enumerate child items and their categories. Never infer flatbed, feeder,
   duplex or film support from a model name.

No background polling, Windows selection dialog, registry scan, vendor utility,
driver installation, or automatic connection is allowed in v1.

## Capability mapping

- Flatbed requires a transfer-capable flatbed category item.
- Feeder requires a feeder item. Duplex requires the reported duplex
  capability/selection property; advanced front/back settings require the
  corresponding child items.
- DPI comes from the reported `WIA_IPS_XRES` and `WIA_IPS_YRES` list/range.
  The adapter exposes only compatible pairs and never fabricates resolutions.
- Colour mode comes from `WIA_IPA_DATATYPE`; bit depth comes from the related
  depth/channel properties.
- Crop bounds come from position/extent and reported physical-size limits.
- Preview, page count, warm-up and transfer controls are exposed only when the
  selected item reports the necessary properties or capabilities.

Property metadata must be read before values are written. A request is rejected
unless every requested value is in the driver's list/range/flags. After setting
properties, the adapter reads them back because a driver may coerce dependent
values. The accepted read-back values become the scan metadata.

## Transfer and cancellation

Use the WIA 2.0 transfer interface on the selected transfer-capable item. The
callback reports bounded progress and checks cancellation without exposing raw
driver messages. Limits apply before and during transfer: maximum page count,
per-page bytes, total batch bytes, dimensions and elapsed time. A feeder-empty
condition after at least one complete page is distinct from corruption, jam,
cancellation and device loss.

Each received page is written to a project-owned stage file. Only a complete,
decodable image with dimensions consistent with read-back properties may be
published as a new immutable master revision. Cancellation or failure removes
only the adapter's own incomplete stage; previously published masters and the
last committed session manifest remain unchanged.

## Error and privacy contract

The adapter maps HRESULT/device conditions to stable codes such as
`device_unavailable`, `unsupported_request`, `feeder_empty`, `paper_jam`,
`cancelled`, `transfer_limit`, `invalid_image`, and `driver_failure`. Display
text is bounded and generic. Raw HRESULT values may appear only in a local
diagnostic field when explicitly enabled, never with WIA IDs, paths, property
contents, or scan bytes.

## Hardware-free tests required before live use

1. Mock no-device, one-device and multiple-device enumeration.
2. Item trees for flatbed-only, feeder-only, simplex and simple/advanced duplex.
3. Property list/range validation, dependent-value coercion and malformed
   property types.
4. Single page, multi-page, cancellation, feeder empty, jam, device loss,
   oversized transfer and invalid image.
5. Confirm failed operations preserve all committed masters and manifests.
6. Confirm no device identifier or private transfer content reaches logs.

Live enumeration and scanning require separate explicit authorization. Static
tests cannot establish compatibility with any scanner model.

## Implemented hardware-free evidence

- `wia_discovery_model` filters scanner-class records, validates bounded public
  metadata, replaces raw driver identifiers with per-refresh opaque tokens,
  and rejects stale selections after refresh.
- `wia_capability_model` maps flatbed, feeder, simple/advanced duplex,
  list/range/flag properties, compatible X/Y DPI, colour modes, bit depths,
  and page limits. Malformed driver properties become sanitized issue codes.
- `wia_transfer_model` enforces page/byte/dimension limits and distinguishes
  complete batches, short feeder batches, cancellation, empty feeder, jam,
  device loss, invalid image, and protocol-order failures.
- `wia_worker_model` enforces the value-only worker lifecycle: stopped, idle,
  refresh, connect, scan, cancellation completion, and shutdown. It rejects
  concurrent operations and refuses shutdown while an operation is active.
- `wia_com_worker` owns a serialized request queue on one dedicated Windows MTA
  thread. COM initialization/uninitialization and injected-backend open,
  execution, and close all occur on that thread. Only bounded value requests,
  replies, cancellation state, and sanitized issue codes cross the boundary;
  the pending queue and device-selection fields are explicitly bounded.
- Fake apartment/backend tests verify FIFO execution, thread affinity,
  cancellation, active/queued shutdown, initialization failure, and exception
  sanitization without calling WIA or touching a scanner.
- `wia2_backend` is the dormant production implementation. When explicitly
  opened on the worker it creates `IWiaDevMgr2`; only an explicit refresh can
  enumerate active local scanner entries. It reads the WIA device ID, name, and
  vendor description, bounds/converts them, and passes them through
  `wia_discovery_model` so raw IDs remain worker-private. Construction alone
  performs no COM or device operation.

The production backend has not been invoked against this machine. Connection,
`IWiaItem2` tree mapping, scan-property read/write/read-back, and image transfer
remain unimplemented. These models, worker host, and dormant refresh code are
not evidence that any installed or attached scanner works.
