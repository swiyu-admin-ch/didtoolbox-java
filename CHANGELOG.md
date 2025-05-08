# DID Toolbox changelog

| Version   | Description                                                                                                                                                                                                                               |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1.3.1** | Further (overloaded) constructors introduced for `Ed25519VerificationMethodKeyProviderImpl`                                                                                                                                               |
| 1.3.0     | Supplying multiple `updateKeys` via existing `-v` CLI param. Loading signing/verifying keys from the [Securosys Primus HSM KeyStore](https://www.securosys.com/de/hsm/hsm-overview) via new `--primus-*` CLI params                       |
| 1.2.0     | Various security issues fixed for Public Beta, e.g. [Swiss e-ID interop profile](https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh). New safety flag (`-f`) for `create` command |
| 1.1.0     | Allow update of existing DIDs [Trust DID Web - did:tdw - v0.3](https://identity.foundation/didwebvh/v0.3/)                                                                                                                                |
| 1.0.0     | Allow creation of new DIDs supporting method [Trust DID Web - did:tdw - v0.3](https://identity.foundation/didwebvh/v0.3/)                                                                                                                 |
