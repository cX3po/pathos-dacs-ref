# DACS discovery artifacts

This directory is the host-ready output of `npm run discovery-gen`. Map the files to the
same-origin routes represented by their paths; HTTP deployment is intentionally separate.

The checked-in `reference-dacs1-listing.json` is a neutral conformance fixture, not a live
offer or cryptographic receipt: a signed DACS-1 §6.3.4 Listing (`dacsVersion` "1") whose seller
presents its IdentityBundle under a self-certifying agent DID (`did:demos:agent:<pubkey>`, a
deterministic test key), signed over the signature-excluded JCS hash, with the Standard's members
and the CF-4 `logical_address` the anchored record carries as metadata (§6.3.4(b); it must equal the
address derived from seller/listingId/listingVersion; the program name is the pinned dacs-sdk's form,
the logical address with each ':' percent-encoded).
`listing-pub --dry-run` verifies it the way a counterparty would before deriving those
coordinates. Re-run the generator with a real immutable `stor-` locator when preparing deployment.

For records anchored before §6.3.4(b), pass
`--legacy-record-without-logical-metadata`. The generator does not mutate the record; its index
entry marks the binding `logicalAddressMetadata: "legacy-absent"`.
