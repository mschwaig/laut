# Verifiable SBOM paper implementation


This is the code that goes along with my Verifiable SBOM paper.

Since implementing this in Nix itself "for real" would take a lot of work, I can do the signature generation and verification completely independently.
I can make 2 builders trust nothing and re-build every build step, uploading he results to a shared cache via a post build hook, including two signatures.
The original signatures that Nix uses, and a constructive trace based signature based on my scheme.
I could do this for input-addressing, content addressing or both, execept that the with input-addressing the cache can only resolve each path one way.
I can even use a different computation to end up with unresovled and resolved derivation hashes, it does not have to match 100%.
It would be good if it at least matches for unresolved / derivations though, but not required.

For verification I just run my tool first, with the defined trust model, and if this succeeds, I run nix build.
Then I check if both tools are in agreement about the output and its runtime closure.

Of course in reality they could be disagreeing now, but this ugliness will disappear, if Nix adopts my verification.

TODOs/next steps:

* figure out if legacy signatures should be allowed closer to the root of the dependency tree than regular signatures or not
* I want to implement some design, which includes the runtime closure of a build step its resolved derivation and therefore input hash, and does this the same way for both input and content addressed derivations.
  This should give us the option to be stricter when resolving input addressed derivations, but also sufficiently strict when a content addressed derivation depends on an input addressed derivation.
  On the other hand, in a content-addressed derivation only world/for an implementation which does not support input addressing, the whole design should just 'dissapear into nothingness'.

I think what we can do is
* for a given build step walk thorugh its runtime closure, and returning all input addressed derivations which are in there, (in some sorted order?).
* Then we resolve all of them to their specific content hashes, and make that part of a specific dedicated section in the resolved derivation, where we either place KV pairs of unresolved, resolved, or the resolved derivations in a defined order.
In unresolved derivations, this list is not present.
In resolved derivations, which do not have any input addressed derivations in their runtime closure, this list is also not present, or empty, depending on how we want to define it.
In resolved derivations, which depend on some input addressed dreivations, the list is filled accordingly.
Same thing for input addressed derivations.

Resolved derivations are used to build input hashes or traces, and this works for input addressing as well as content addressing.
It's just that for input addressing we can choose to ignore this, to get the current semantics with frankenbuilds, and for content addressing we would have to relax the security model and use rewrites to get back to those original semantics.

The violations of those semantics we actually care about are when two different resolutions of the same unresolved input end up in the same buildtime closure.(Also actually true purely in content addressing, but not sure yet how we would handle that either ...)

This might actually work and not be an issue, but with how I have written the above, in the key value scenario, we could not even express conflicting resolution of an input-addressed indirect dependency. So we might detect this situation, and its purely content-addressed variant, and add a suitable rewrite to the derivation. Not sure how else we would handle this.
The correct place to hint about how we did such rewrites might be in the response to the unresolved input hash .... i would say narinfo, but sice that's per path and not per derivation it does not seem totally appropriate.
We might not have to query for this information if we do not have any trouble with such conflicting resolutions.

During dependnecy resulution such a rewrite actually creates a constraint on the resoultion. Once we have resolved the dependencies, this constraint should be satisfied, or it should have lead to an error.
Another possible constraint could be that a rewrite is not allowed to occur between a derivation e and its upstream dependency d.

It is not clear to me if the presence of a rewrite should have an impact on the hash of the derivation as well, or be implied by this closure resolution section we are designing right now.

Ok, this still misses the cases where we have different content addressed derivations depending on something with the same unresolved identity but a different resolved identity.
For this we would have to scan the runt time closure of all derivations and record how each unresolved dependency is resolved.
Then we could detect this situation, and choose to resolve it via adding an entry to the special extra section, or not, or we could make adding an entry to the special extra secttion, and therefore/at the same time making a rewriting decison mandatory. The tough thing about his is that the rewriting would then again impact identity, and I am not sure how to model this recursive mess, so it is clear to both producer and consumer.

I know how this can work now, for both cases.
We initially put out a request to the cache, using a resolved input hash, which contains the conflict (we should at the same time locally already be aware of the conflict, so the endpoint could also be different, and what we get back from upstream still has to conform to our trust model). This does not muddy the water the same way as giving back build results for arbitrarily unresolved derivations would, because we are actually going to get back a signature for an entirely differnt kind of build step: a rewrite.
It tells us how upstream resolved this conflict. If their resolution fits within our trust model, we can also perform it, in anticipation of this helping uns get downstream stuff from their cache as well.
We can also resovle completely differnetly or just not consult anybody about this conflict resolution at all and simply do it locally.
Either way we end up with a new input hash based on the rewritten inputs, and can proceed from there, for example by requesting that from the cache.

Some of the content addressed paths in our store might have been rewritten now, but we keep the corresponding signatures around, and hopefully the signed rewrite (or a signed rewrite we produced ourselves) makes it clear what chain of operations produced all of those outputs in our store.
Maybe we can re-use the same primitive to reason about trivial differences in storepaths, ... i have to think about this more.

RECOMMENDATIONS by numinit
https://www.usenix.org/system/files/1401_08-12_mickens.pdf
https://fidoalliance.org/wp-content/uploads/2024/06/EDWG_Attestation-White-Paper_2024-1.pdf


This is an educational POC which might or might not be turned into a reference implementation at some point.

It would be nice to demonstrate, that it works with Nix, Lix and Guix.