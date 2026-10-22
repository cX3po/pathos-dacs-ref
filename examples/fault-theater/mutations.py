"""Synthetic bundle mutation fixtures; no RPC, wallet, or private dependencies."""
import json
import sys
MUTATION_NAMES = ("finality-removed", "chain-identity-replaced", "content-changed", "vet-pass-forged", "role-signature-broken")

def mutation_targets_missing(data: dict) -> list[str]:
    """Fields every named mutation needs to exist; a missing target is reported, never fabricated."""
    missing = []
    if "finalisedAt" not in data:
        missing.append("finalisedAt")
    phases = data.get("phaseSummary")
    if not (isinstance(phases, list) and any(isinstance(p, dict) and isinstance(p.get("txRefs"), list) and p["txRefs"] and isinstance(p["txRefs"][0], dict) and "kind" in p["txRefs"][0] for p in phases)):
        missing.append("phaseSummary[].txRefs[].kind (a chain identity in the signed scope)")
    if "outcome" not in data:
        missing.append("outcome")
    if not isinstance(data.get("vetRecords"), list):
        missing.append("vetRecords")
    evidence = data.get("settlementEvidence")
    if not (isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) and isinstance(evidence[0].get("anchor"), dict) and isinstance(evidence[0].get("contentHash"), str)):
        missing.append("settlementEvidence[0] (an anchored artifact a forged vet reference can cite)")
    sigs = data.get("signatures")
    if not (isinstance(sigs, list) and sigs and isinstance(sigs[0], dict) and isinstance(sigs[0].get("value"), str) and sigs[0]["value"]):
        missing.append("signatures[0].value")
    return missing

def _mutations(data: dict) -> dict[str, dict]:
    """Five mutations of one bundle object, each on its own deep copy, each named for the class it exercises:
    finality-removed        the signed finalisedAt member is removed;
    chain-identity-replaced the chain named by every ChainTxRef in the signed phaseSummary is replaced (demos -> ethereum);
    content-changed         the signed outcome flips (completed <-> faulted);
    vet-pass-forged         a schema-valid vetRecords AttestationRef is added that cites an existing anchored artifact (the
                            first settlement evidence) as if it were a composite verification record with a pass: an
                            offline forgery that resolves on the node to bytes of the wrong artifact kind. A forged
                            composite record served through an offline reference resolver is not supported by either
                            command-line verifier, so that variant is not claimed;
    role-signature-broken   the decoded bytes of the first role signature change; the signed scope does not.
    Call mutation_targets_missing(data) first; these functions assume the targets exist."""
    import copy
    out: dict[str, dict] = {}
    m = copy.deepcopy(data); m.pop("finalisedAt"); out["finality-removed"] = m
    m = copy.deepcopy(data)
    for ph in m["phaseSummary"]:
        if isinstance(ph, dict) and isinstance(ph.get("txRefs"), list):
            for ref in ph["txRefs"]:
                if isinstance(ref, dict) and "kind" in ref:
                    ref["kind"] = "ethereum" if ref["kind"] != "ethereum" else "demos"
    out["chain-identity-replaced"] = m
    m = copy.deepcopy(data); m["outcome"] = "faulted" if m["outcome"] != "faulted" else "completed"; out["content-changed"] = m
    m = copy.deepcopy(data); cited = m["settlementEvidence"][0]
    m["vetRecords"] = list(m["vetRecords"]) + [{"anchor": copy.deepcopy(cited["anchor"]), "contentHash": cited["contentHash"]}]
    out["vet-pass-forged"] = m
    m = copy.deepcopy(data); v = m["signatures"][0]["value"]
    m["signatures"][0]["value"] = ("A" if v[0] != "A" else "B") + v[1:]
    out["role-signature-broken"] = m
    return out

if __name__ == '__main__':
    bundle = json.load(sys.stdin)
    missing = mutation_targets_missing(bundle)
    if missing:
        raise ValueError('missing fixture targets')
    print(json.dumps({'names': MUTATION_NAMES, 'mutations': _mutations(bundle)}))
