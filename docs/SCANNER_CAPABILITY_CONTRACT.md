# Scanner capability contract v1

Every backend exposes stable provider and device identifiers, a backend kind,
display name, availability state, and an explicit capability set. UI controls
must be derived from that capability set; unsupported options are disabled and
must also be rejected by the core.

The v1 request contains:

- source: `flatbed`, `adf-simplex`, or `adf-duplex`;
- DPI as a positive integer selected from the device's reported set;
- colour mode: `gray8` or `rgb24`;
- bit depth, currently 8 for the mock provider;
- optional maximum page count, bounded to 1 through 10,000.

A provider validates the entire request before starting. Results contain a
fixture-neutral byte stream, declared extension, dimensions, DPI, colour mode,
bit depth, source, and a non-private fixture identifier. Providers must report
errors as typed status codes and must not place paths, device identifiers, or
scan contents in user-facing error messages.

Provider states are independent: enumerate, ready, scanning, cancelling,
completed, or failed. Later WIA and network providers may need more internal
states, but they must map to this public contract without pretending their
capabilities are identical.
