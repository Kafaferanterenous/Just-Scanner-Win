# Clean-room and scope boundary

Status: implementation contract for the first offline mock milestone.

## Independent implementation

Just Scanner is implemented from the project requirements and public behavior
descriptions. External scanner applications may inform high-level workflows,
but their source, assets, schemas, class names, comments, UI layouts, and
implementation structure must not be copied, translated, or line-rewritten.

The current source uses only the C++ standard library and documented Windows
file-replacement APIs. No third-party dependency or external asset is included.
The final project licence remains undecided until every selected dependency and
redistribution obligation has been reviewed.

## First milestone boundary

In scope:

- a replaceable scanner-provider interface;
- explicit device capabilities and request validation;
- deterministic sanitized mock scans;
- non-destructive session and page operations;
- bounded persistence and interrupted-save recovery tests.

Out of scope until later gates:

- WIA, TWAIN, eSCL/WSD, SANE, ImageCaptureCore, or live devices;
- network discovery or requests;
- PDF, JPEG, PNG, TIFF codec dependencies;
- OCR engines, models, language packs, or downloads;
- GUI frameworks, installers, services, telemetry, or accounts.

## Privacy and safety

Fixtures must be synthetic and contain no names, addresses, document images,
device serial numbers, or other personal data. Originals are immutable once
published. Excluding a page changes session state but does not delete its
master file. Rescanning publishes a new revision and preserves the old master.
Session replacement uses a staged file and backup; incomplete stage files are
never treated as the current session.
