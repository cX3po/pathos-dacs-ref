# DACS agent configuration

Copy `dacs-agents.example.json` to `dacs-agents.json`, then export the environment variables named by each agent's `mnemonicEnv`. The local file is gitignored; key material belongs only in the operator's environment.

This configuration is testnet-only. Use faucet DEM only—never production funds.

`dacs-agents.example.json` is an example of one local layout for this reference implementation. It is not a schema or a format anyone else is expected to adopt; other implementations keep whatever agent configuration suits them. Identities themselves follow the Demos SDK's own CCI claim representation (`demos:<address>` claim references), so nothing here defines an identity format.
