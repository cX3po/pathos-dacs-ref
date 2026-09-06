# DACS-Standard conformance fixtures (verbatim copies)

Copied from `conformance/fixtures/` of DACS-Agent-commerce/DACS-Standard at commit 18b385b6
(the checkout reviewed for PR #350; the two files last changed in 8e1119b "Fix artifact reference
conformance shapes"):

- settlement-evidence-payment-success.json
- settlement-evidence-delivery-success.json

Their `evidence` member is the DACS-4 §9.7 wire record the pinned dacs-sdk (3aa1d7df) validates:
no phaseIndex in the body (§9.5.8 SB-1) and `paymentTxRefs` as §9.7 ChainTxRef arms. `evidenceHash`
is the hash the Standard states for the record; `publicKeys` carries the fixture signer's key.
