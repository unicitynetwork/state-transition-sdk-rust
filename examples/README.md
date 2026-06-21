# Examples

Runnable example flows, talking to a
**live aggregator** through [`HttpAggregatorClient`].

| Example | Reference | Run |
|---------|-----------|-----|
| `mint` | `state-transition-sdk-js/tests/examples/mint` | `cargo run --example mint --features http` |
| `transfer` | `.../tests/examples/transfer` | `cargo run --example transfer --features http` |
| `split` | `.../tests/examples/split` | `cargo run --example split --features http` |

Each example prints the resulting token's CBOR as hex, exactly like the model
examples (`console.log(HexConverter.encode(token.toCBOR()))`). `split` mints a
coin carrying a fungible payload, splits it into several coins (burning the
original), and prints each minted output after verifying it fail-closed with
`payment::verify_payment_token`.

## Configuration

Connection parameters are read from `e2e/.env` (copy `e2e/.env.example` and set
your key):

```
UNICITY_GATEWAY=https://gateway.testnet2.unicity.network/
UNICITY_API_KEY=sk_…
UNICITY_TRUSTBASE=bft-trustbase.testnet2.json
```

Values already present in the process environment take precedence. The examples
require the `http` feature (a blocking TLS HTTP stack); they generate ephemeral
in-memory wallets and never persist keys.

For a fuller standalone demo (mint → save → reload → transfer → verify), see the
`e2e/` crate.
