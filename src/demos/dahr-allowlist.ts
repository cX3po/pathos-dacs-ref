/**
 * DAHR hostname allowlist — v0.2 SSRF defense
 *
 * Spec context: DACS v0.7 §7.3.5 consensus-backed-proxy. The full DAHR primitive
 * routes fetches through a Demos validator, which is responsible for refusing
 * to hit private-network targets. Our v0.2 stub fetches directly from the local
 * process — so we have to do the SSRF defense ourselves.
 *
 * For v0.2 scope (only the GLEIF recipe is wired), an explicit hostname allowlist
 * is the right scope-discipline tool:
 *   - Smaller attack surface than IP/CIDR blocklists
 *   - Forces a deliberate code-edit per new recipe
 *   - Makes the "which authorities does this implementation actually hit" question
 *     answerable by reading one file
 *
 * As we wire more recipes (ECB, FedRAMP, OFAC, etc.) we extend this list. When
 * v0.3 swaps to true validator-backed-proxy DAHR, this allowlist becomes advisory
 * (the validator quorum enforces network-layer policy at the substrate layer).
 *
 * Known limitation: this does NOT defend against DNS rebinding (where api.gleif.org
 * resolves to 127.0.0.1 on second lookup). v0.2 mitigation: callers are trusted
 * (this CLI is operator-driven, not a public endpoint). v0.3 will resolve once
 * and pin the resolved IP for the lifetime of the fetch.
 */

/** Hosts the v0.2 DAHR primitive is allowed to fetch. v0.2 only wires the GLEIF recipe; the allowlist contains exactly that one host. */
export const DAHR_HOST_ALLOWLIST: ReadonlyArray<string> = [
  'api.gleif.org',         // DACS-2 §7.3.5 GLEIF recipe — the only wired recipe in v0.2
] as const;

/**
 * Roadmap — hosts that get added as recipes ship (Codex round 6 #2 scope-discipline):
 *   - api.frankfurter.dev     (DACS-2 §7.3.5 ECB rate recipe — v0.3 candidate)
 *   - cloudflare-dns.com      (DACS-2 §7.3.8 DNS-over-HTTPS — v0.3 candidate)
 *   - api.sam.gov             (DACS-2 §7.3.5 SAM.gov recipe — v0.3 candidate)
 *   - api.brokercheck.finra.org (DACS-2 §7.3.5 FINRA recipe — v0.3 candidate)
 *   - marketplace.fedramp.gov (DACS-2 §7.3.5 FedRAMP recipe — v0.3 candidate)
 * Add to DAHR_HOST_ALLOWLIST in the same commit that wires the corresponding recipe.
 */

/**
 * Hosts explicitly allowed only when DACS_TEST_NETWORK=1 is set.
 * Used by integration tests that hit example.com etc. — never used in production CLIs.
 */
export const DAHR_HOST_ALLOWLIST_TEST: ReadonlyArray<string> = [
  'example.test',
  'example.com',
] as const;

/**
 * Check whether `hostname` is allowed under the current DAHR allowlist.
 * `hostname` should be the value of `new URL(url).hostname` — already lowercased.
 */
export function isAllowedHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (DAHR_HOST_ALLOWLIST.includes(lower)) return true;
  if (process.env.DACS_TEST_NETWORK === '1' && DAHR_HOST_ALLOWLIST_TEST.includes(lower)) return true;
  return false;
}

/**
 * Throw a descriptive error if `hostname` is not on the allowlist.
 * Used internally by dahrFetch() — exported here for tests.
 */
export function assertAllowedHost(hostname: string): asserts hostname is string {
  if (!isAllowedHost(hostname)) {
    const known = DAHR_HOST_ALLOWLIST.join(', ');
    throw new Error(
      `DAHR v0.2: host "${hostname}" is not on the allowlist. ` +
      `Known authorities: ${known}. ` +
      `Add new hosts to src/demos/dahr-allowlist.ts as new DACS-2 recipes get wired.`
    );
  }
}
