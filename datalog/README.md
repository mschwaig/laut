Modeling nix dependency verification in datalog/souffle

We have the following entities

* unresolved derivation (by hash of drv)
* resolved derivation (by hash of resolved drv)
* output (by content hash)

We have the following relationships

* Each unresolved derivation can be resolved in a number of ways, to a resolved derivation.
* Each resolved derivation can be built to obtain an output with  a given content hash.

We get a few files as inputs

1. unresolved dependency relationships
hash of unresolved drv, hash of unresolved drv it depends on

2. resolved dependency relationships
hash of resolved drv, hash of unresolved drv it resolves from, hash of unresolved drv it depends on, content hash of resolved drv it depends on

3. builds
hash of resolved drv, content hash of output

from this we want to compute an output file, which contains information about each derivation:
hash of unresolved drv, hash of resolved drv, hash of output

Verification should check taht every dependency is satified.

See https://claude.ai/share/cc79b945-ba56-407b-8c59-4266c512d42f for how the souffle code was initially generated.
