# wheel-crypto-scan

Reports crypto-relevant **evidence** found inside Python wheels: which primitive families
and libraries are present, how they are linked, what the Python code does with TLS,
hashing and randomness, and whether post-quantum algorithms show up. That is the account
a package index's consumers get, wheel by wheel.

FIPS compatibility is one lens over that account, not its whole purpose: whether a
FIPS-enforcing host can run the wheel's crypto as shipped, so consuming teams can gauge
FIPS risk before they ship it. It gathers evidence. It does not decide FIPS compliance.

## Install and run

```bash
uv tool install .                       # or: uv run wheel-crypto-scan
wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
```

Full docs — the FIPS lens, every flag, the output schema, the ruleset, and the design
calls that cost something: **<https://my1.fr/wheel-crypto-scan/>**

## Development

```bash
uvx --with tox-uv tox          # tests across py311-py314, plus ruff lint and format
uvx --with tox-uv tox -e lint
```

See [Contributing](https://my1.fr/wheel-crypto-scan/contributing/) for adding policy,
changing extraction, writing up a design call, and releasing.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
