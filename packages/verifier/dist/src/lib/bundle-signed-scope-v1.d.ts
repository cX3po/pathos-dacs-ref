/**
 * Compute the v0.1 bundle signed-scope hash (hex). Strips BOTH `signatures` and `anchoredByRole`
 * itself, so it is safe to call on a full bundle OR a signature-less one (misuse-proof — a caller
 * that passes a full bundle still gets the correct signed scope). `signatures` is the §10.4.1
 * exclusion; `anchoredByRole` is the R5-1 exclusion.
 */
export declare function bundleSignedScopeHashV1(bundle: Record<string, unknown>): string;
