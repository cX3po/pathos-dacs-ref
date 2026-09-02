# Native DEM payment policy

The live Organ Gateway requires an operator payment policy before it connects to the Demos testnet. Set `DACS_PAY_POLICY` to the path of a JSON policy file. If the variable is absent, the file cannot be read, or the JSON is invalid, the live gateway exits before any transfer is prepared or signed. Immediately after loading it, the gateway performs a pre-connect preflight against the configured RPC host, the fixed transfer price in integer OS, the kill switch, and the current journal total. A block exits with status 2 before `connectLive()` can load credentials or contact an RPC endpoint.

The repository example is [`config/pay-policy.example.json`](../config/pay-policy.example.json):

```json
{
  "network": "testnet",
  "rpcHosts": ["demosnode.discus.sh"],
  "perTransactionCapDem": "5",
  "dailyCapDem": "25",
  "killSwitchFile": "~/.pathos-dacs-ref/PAY_KILL"
}
```

This policy permits only the testnet RPC host `demosnode.discus.sh`, limits one native transfer to 5 DEM, limits recorded transfers to 25 DEM per UTC date, and blocks transfers while `~/.pathos-dacs-ref/PAY_KILL` exists. Cap comparisons use integer OS values; one DEM is 1,000,000,000 OS. Equality with either cap is permitted.

Checks run in this order: kill switch, RPC host, per-transaction cap, then daily cap. The same checks run again at settlement time before the recovery preparation is journaled and before the client creates or signs a transaction. The kill switch is checked once more immediately before broadcast.

The daily total is local to the configured `DACS_PAYDEM_JOURNAL` file. It is not a global total across machines or distinct journal files. Local processes serialize the settlement-time journal read, cap authorization, and pre-broadcast accounting append under an exclusive `O_EXCL` lock file beside the journal. A live owner prevents another transfer from being authorized; abandoned same-host locks and sufficiently old foreign or malformed locks are recoverable under the stale-lock rule. Failure to acquire or validate the lock blocks payment.

Before the irreversible send, the gateway appends and fsyncs exactly one counted record whose outcome is `broadcast-attempted`. If that durable append fails, broadcast does not run. No second counted record is written after success. Failures that occur before broadcast may append `aborted-before-broadcast`, which is excluded; `pre-broadcast-abort` remains accepted as the same exclusion for existing records. `broadcast-attempted` and every other non-abort outcome are counted. Signed-preparation records without `outcome` remain ignored.

Policy-accounting records read exactly three fields: `timestamp`, `amountOs`, and `outcome`. Every timestamp—including the authorization `nowIso`—must be valid ISO text with an explicit `Z` or `±HH:MM` timezone. The authorization timestamp is captured once and reused on the pre-broadcast counting record. If the UTC date changes before broadcast, the transfer is blocked and must be authorized again against the new day. `amountOs` must be a canonical non-negative integer string and `outcome` a non-empty string. A malformed outcome record or unreadable journal blocks authorization rather than reducing the total.

The policy does not limit SR-2 storage writes, account balances, non-native assets, or transfers performed outside the pay-dem live path. The existing live spend preflight separately checks its session estimate, configured job cap, balance margin, operator approval, and dry-run binding.
