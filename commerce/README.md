# Commerce artifacts (rehearsal)

One purchasing and delivery contract for the four services PATH-OS can supply once the
operator opens the monetisation door. Nothing here sells anything: the network is
`demos:testnet` in `rehearsal` mode, mainnet is `enabled: false`, and every merchant
identity is `unset-until-deploy`. The files exist so that day one needs a price decision
and a key, not a design.

| File | What it is | Read by |
| --- | --- | --- |
| `offers.json` | Four SKUs priced in canonical DEM strings and integer OS base units, with quote, retry, failure and refund terms and the written paid-order procedure for the three manual services | buyers, the d402 gate, tests |
| `service-manifest.json` | Provider identity slot, profiles, one entry per service with how to submit, where the result lands, and the proof of delivery | buyers, discovery |
| `openapi.json` | The HTTP surface (`/healthz`, `/schemas/*`, `/verify`) with the 402 challenge, the receipt and the retained-proof 503; `x-skus` names the three manually fulfilled services | HTTP clients |
| `discovery-registration.json` | DACS-1-shaped listing draft for the verify service, not yet registry-validated; signed, validated and anchored with `npm run listing-pub` at deploy | the listing publisher |

## The four SKUs

| id | unit | rehearsal price | fulfilment today |
| --- | --- | --- | --- |
| `verify-bundle` | per bundle | 0.1 DEM | automatic, `POST /verify` on `src/live/verify-endpoint.mts` |
| `interop-run` | per pinned run | 5 DEM | manual on the working-group thread; free to the working group |
| `verifier-package` | per versioned package | 1 DEM | builds; registry publication is the operator's door |
| `pr-review` | per PR revision | 10 DEM | manual; free to the DACS working group today |

Prices are rehearsal numbers for testnet. The operator sets mainnet prices when the door
opens; `offers.json` then gets a fresh `network` block and new quotes.

## Invariants (pinned by `test/vectors/commerce-artifacts.test.ts`)

- every SKU id in `offers.json` appears exactly once in `service-manifest.json` and in
  `openapi.json` `x-skus`;
- every `price.amountOs` equals `demToOs(price.amountDem)` from `src/adapters/dacs/pay-dem.ts`
  and is greater than zero;
- `network.mode` is `rehearsal` and `network.mainnet.enabled` is `false` in every file that
  carries a network block; the discovery draft says testnet on, mainnet off, and is unsigned;
- the `verify-bundle` price equals the verify endpoint's default `VERIFY_PRICE_DEM` (`0.1`);
- the JCS hash of each artifact is pinned, so a price or term change is a deliberate diff.

## Proof of delivery

`verify-bundle` returns an HTTP receipt `{txHash, from, amountOs, resourceId}` that names the
on-chain payment and is bound to the SHA-256 of the exact request bytes; the same proof with the same bytes is redelivered, never
billed twice (`docs/verify-endpoint.md`). The other three services deliver a report, a
package with provenance, or a posted review at an exact head, as listed under
`proofOfDelivery` in the manifest. A shared receipt schema across all four is the next item
(`s6-commerce-receipts`).
