# Mock export contract v1

The mock milestone exports only included pages and always follows current
session order. Output publication is staged beside the destination and refuses
to replace an existing filename.

Separate-image PGM export writes a rendered derivative using
`{document_name}_{page_number:04}.pgm`. Crop and rotation are applied first,
then bounded brightness and contrast adjustments; the stored master remains
byte-identical. On Windows, the core can also encode
8-bit grayscale PNG, JPEG, and TIFF through the operating system's native
Windows Imaging Component codecs. These are Windows-only capabilities, not a
claim of cross-platform codec support. JPEG is lossy; PGM, PNG, and TIFF are
the lossless options in this mock slice.

Multipage PDF export embeds each validated 8-bit grayscale PGM as an
uncompressed PDF image object. Page dimensions are derived from pixel size and
DPI. The writer emits a page tree, content and image objects, a complete xref
table, trailer, `startxref`, and final EOF marker. It is bounded to 1,000 pages
and 512 MiB and refuses collisions. Searchability, OCR, compression, metadata,
PDF/A, encryption, signatures, and colour images are not implemented.

Before release, PDFs require independent parser/render validation and malformed
input fuzzing. WIC output requires clean-machine Windows validation. Linux and
macOS PNG/JPEG/TIFF support remains behind a dependency provenance, licence,
codec, and redistribution review.
