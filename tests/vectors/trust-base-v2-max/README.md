# Maximum-size trust base entry (shared fixture)

`max-entry.json` is vendored byte for byte from `unicitynetwork/bft-go-base`, path `testdata/trust-base-v2/max-entry/v1/max-entry.json`, commit `dbf94198f25eaafd5e97f8af29969f7374f9b303` (merged as #20; the same bytes as at the earlier `81ee667` of ristik/bft-go-base `utb/gettrustbase-codec`); never edit this copy.

SHA-256: `c4c5970307c1780fa08108529e3ef9e37803726b6df1843d61c8421f97a795b6`

Network 5. Epoch 1 is a genesis of 256 members with 128-byte node ids (the pin is `genesisId`); epoch 2 has the same members and a signature of all 256 predecessors: 95,365 bytes, the largest valid entry. Fields: `genesis`, `genesisId`, `entry`, `entryId`, `entryBytes` (the entry's length), `bundle` (the two-entry tag-39015 bundle). The per-entry cap is 128 KiB; pages stay 1 MiB / 64 entries.
