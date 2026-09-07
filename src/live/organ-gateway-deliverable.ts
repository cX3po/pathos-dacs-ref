/**
 * organ-gateway-deliverable.ts — the organ gateway's deliverable, built through the coordinator's public answer
 * projection so the gateway path has the same confidentiality boundary as the LIVE coordinator: only the projected
 * public answer, the commitment, its scheme and fetched_at are anchored; the commitment nonce is returned to the
 * caller for off-channel retention and never appears in the deliverable. A bridge output that fails validation or
 * projection is an OrganDeliverableError before any anchor write.
 */
import { organDeliverableFrom, OrganDeliverableError, type OrganDeliverable } from './dacs-testnet-run.mjs';

export interface GatewayDeliverable extends OrganDeliverable {
  /** The agreement this delivery fulfils (the gateway's DACS-3 agreement hash). */
  agreementHash: string;
}

const NONCE = /^[0-9a-f]{16,128}$/;

export function gatewayDeliverableFrom(raw: string, run: { jobId: string; organ: string; agreementHash: string }): { deliverable: GatewayDeliverable; commitmentNonce: string } {
  const projected = organDeliverableFrom(raw, { jobId: run.jobId, organ: run.organ });
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new OrganDeliverableError('organ bridge output is not JSON'); }
  const nonce = (parsed as { commitment_nonce?: unknown }).commitment_nonce;
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) throw new OrganDeliverableError('organ bridge nonce is missing or not a hex string');
  if (typeof run.agreementHash !== 'string' || !/^[0-9a-f]{64}$/.test(run.agreementHash)) throw new OrganDeliverableError('agreement hash is not a 64-hex digest');
  const deliverable: GatewayDeliverable = { v: projected.v, jobId: projected.jobId, agreementHash: run.agreementHash, organ: projected.organ, answer: projected.answer,
    input_commitment: projected.input_commitment, commitment_scheme: projected.commitment_scheme, fetched_at: projected.fetched_at };
  if (JSON.stringify(deliverable).includes(nonce)) throw new OrganDeliverableError('organ bridge nonce would be anchored');
  return { deliverable, commitmentNonce: nonce };
}
