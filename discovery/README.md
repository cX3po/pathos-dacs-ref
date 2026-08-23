# DACS discovery artifacts

This directory is the host-ready output of `npm run discovery-gen`. Map the files to the
same-origin routes represented by their paths; HTTP deployment is intentionally separate.

The checked-in `reference-source-listing.json` is a neutral conformance fixture, not a live
offer or cryptographic receipt. It demonstrates the required go-forward shape: registered
`key:` ClaimReference, CF-4 `logical_address` carried on-record, a signature field excluded
from DACS `contentHash`, and a published logical→native binding. Re-run the generator with a
real immutable `stor-` locator when preparing deployment.

For records anchored before §6.3.4(b), pass
`--legacy-record-without-logical-metadata`. The generator does not mutate the record; its index
entry marks the binding `logicalAddressMetadata: "legacy-absent"`.
