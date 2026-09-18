"""Layer extractors: metadata, native binaries, Python source, plus the inventory.

A layer function takes the archive plus its own half of the compiled patterns and
returns `(evidence, errors)`, each ordered by a stable key so the same wheel gives the
same record on every run. It never raises for one bad member: a member it cannot read
becomes a `ScanError` alongside whatever the rest of the traversal found.

`read_metadata` takes a member list and a reader rather than the archive, so it can be
exercised without a zip, and `build_inventory` counts what the other three already
found, so it returns an inventory and no errors of its own.
"""
