# Verifiable SBOM paper implementation


This is the code that goes along with my Verifiable SBOM paper.

Since implementing this in Nix itself "for real" would take a lot of work, I can do the signature generation and verification completely independently.
I can make 2 builders trust nothing and re-build every build step, uploading he results to a shared cache via a post build hook, including two signatures.
The original signatures that Nix uses, and a constructive trace based signature based on my scheme. I can do this for input-addressing, content addressing or both.
Having one builder be input-addressed and one be content-addressed might even be interesting.
I can even use a different computation to end up with input-addressed derivation hashes, it does not have to match 100%.
It would be good if it at least matches for input addressed derivations though, but not required.

For verification I just run my tool first, with the defined trust model, and if this succeeds, I run nix build.
Then I check if both tools are in agreement about the output and its runtime closure.

Of course in reality they could be disagreeing now, but this ugliness will disappear, if Nix adopts my verification.
