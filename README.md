## laut /laʊt/ - verifiable provenance data and SBOMs with Nix

The name is german for[^1]
* loud, noisy, blatant 📢
* (as) per, according to, in accordance with 🕵️‍♀️

<div align="center">

---

🚧 This is a currently very incomplete implementation of https://dl.acm.org/doi/10.1145/3689944.3696169. 🚧

---

</div>

The fundamentals are in place, but none of the cool things about this are implemented and working yet: 🙈
* configurable trust model[^2], ...
* which can be re-configured over time, based on ...
* verifiable provenance data for builders
* like realizations for CA derivations, ✅ but also works for IA derivations
* based on a new proposed signature format on top of JWS, ✅ with
* arbitrary additional ✅ but detachable metadata
* integrates with/extends https://github.com/nikstur/bombon to create verifiable SBOMs

Right now this can resovle the dependencies for and verify a fully content-addressed `hello` binary, with a single key, in our VM tests.

At the same time, it's not ready for users yet.
If you want to try this yourself outside of those tests, be prepared for surprises, because
* the input hashes depend on the stability of nix derivation show, which is not stable across implementations,
* passing more than one key does not do the correct thing yet,
* I have not figured out how to retrieve the signatures from S3 outside the VM test. :see_no_evil: I’m new to the S3 API.

I'm not even putting the format being unstable on the list that's how unstable it is.
While conceptually this being OK the point of this format, it will lead to soOoOo much cache invalidation for the time being, that as a consumer you will just want to throw thow all those signatuers out still.

I want to get a scientific paper, and later my PhD thesis published based on this work, so if you do something that's inspired by this project, please give me a shoutout in your README.md, your docs or the relevant issue in your issue tracker. This really helps me demonstrate the relevance of my work.

### How can I use it

This is a standalone command line tool called `laut`,  which has two subcommands:

The first one is
```
laut sign-and-upload --to [S3 store url]
```

which will sign your derivations with the new signature format, and upload them to the newly introduced `traces` folder in the provided S3 store. This will then happen automatically after each build, in the same way that signatures are normally uploaded from nix-based builders.

The second one is
```
laut verify --from [S3 store url] --trusted-key [private key for signing] [derivation path or flake output path]
```

Which is run manually by the user after building or obtaining an output from the cache.
This command tries to verify that a given derivation is valid according to the stricter validation criteria of the tool. Later on there will be more options to configure a specific trust model to verify against, and you will be able to additionally pass an SBOM which then also has to match the other elements. The goal of the SBOM integration is to connect this with established standards that people outside of the Nix community understand as well.

### How does it work

It's a python program. The signing is very straightforward python code.

The verification is more complicated, as it instantiates an actual dependency tree in memory, then walks through that tree and emits facts about the dependency tree to some files.
As part of this verification phase, the tool also gathers signatures from a set of caches, taking into account possible combinations of inputs by content hash, which could satisfy the dependency on those same inputs by input hash.
These files then serve as the input to a datalog program using SWIG, to make the actual determination about the validity of the dependency tree.

The datalog program is compiled using souffle inside of its own derivation.

### How can I test it

As of now, there are two kinds of tests in this project

The python tests, which can be run with

```
pytest -s tests/
```

inside a nix develop shell, and the NixOS VM tests, which you can run by first building the test driver for one of the tests
```
nix build .#checks.x86_64-linux.fullReproVM.driverInteractive 
```

and then running the resulting binary to get into this emacs shell.

In that shell you can then run the test using the "test_script()" function.

**In the future** each VM test should validate according to a different trust model, but right now there is no meaningful distinction between them yet.

We can also test our reasoning about trust relationships directly in datalog, in a another set of tests.

### FAQ

**Q:** Do you want to upstram this?  
**A:** Yes. With this project, I want to lead a credible effort to propose a specific signature format, which does what I want from such a format, as outlined in my paper.

**Q:** Do you accept contributions?  
**A:** Yes, I am enthusiastic about collaborating on this, and helping people with getting started on that. I also want to reply to proposals and criticism within a week. If I don't and you're waiting on an answer from me, please remind me.

**Q:** What do you want from a signature format in Nix?  
**A:** To turn Nix into a leading edge supply chain security tool. Nix has interesting properties in that area, but it is not living up to its potential yet.

**Q:** Are you interested in working with different implementations of Nix?  
**A:** Yes, definitely. I feel like a flexible enough signature format can be especially useful in an increasingly diverse ecosystem. Let's make it possible to let Nix evolve over time, try new ideas, AND interoperate as much as possible while doing it. It's important to me to have a good working relationship with others in the community across various implementations of Nix, who care about these issues as well.
  Please open issues, reach me on matrix or via email at m@groundry.org.

**Q:** Why are you not implementing this in Nix or any of its implementations directly?  
**A:** Eventually that is definitely the way you would want to do this kind of thing, but for now it is meant to prove the concept (also across implementations) and introduce it to an expert audience, with a lot of breakage much shorter iteration times.

**Q:** Can I use this now?  
**A:** No, it does not do anything useful yet, but you can help work on it.

### Glossary

Here is a list of technical terms we use in this project with their definitions:

<dl>
  <dt>derivation / drv</dt>
  <dd>Nix uses this term for build steps, which are identified and defined by their characteristic input hash. In this project we will define a derivation strictly as an element <code>i</code> in the domain of a function <code>build(i: input) -> output</code> and not as the pair of both input output <code>(i, build(i))</code>.</dd>
  <dt>unresolved derivation</dt>
  <dd>A derivation, which depends on other derivations.</dd>
  <dt>resolved derivation</dt>
  <dd>A derivation, which does not depend on other derivations (anymore). The content-addressed derivation RFC also calls this a basic derivation.</dd>
  <dt>derivation output / output path</dt>
  <dd>Each derivation can have more than one derivation output, which show up in the Nix store as/at separate output paths, but were created by building the same derivation. This step of indirection and distinction between individual outputs of a derivation is not an important concern when reasoning about trust, but it shows up in the technical details sometimes. Derivation outputs refers to the abstract names of these outputs, written as <code>/nix/store/{hash}-{name}.drv$out</code>, while output path refers to their "physical manifestation" in terms of a path / address and the contents of those outputs in the store, like <code>/nix/store/{hash}-{name}</code> and its content.</dd>
  <dt>content hash</dt>
  <dd>Describes the bitwise identity of a file or path by hashing it in a defined manner.</dd>
  <dt>dependency resolution / resolution</dt>
  <dd>The process of resolving a derivation, by replacing each dependency on another derivation in terms of a derivation output of another unresolved derivation with its bitwise identity in term of a content hash.
  <br>
  The following adds detail using a bunch of forward references:
  For derivations using the CA derivation experimental feature, this is done explicitly by replacing entries in the <code>inputDrvs</code> attribute of the drv with entries in the <code>inputSrc</code> attribute of the drv. For IA derivations or CA derivations with IA dependencies, this happens implicitly every time the contents of an IA path are accessed.</dd>
  <dt>input hash</dt>
  <dd>The identifying and defining hash of a derivation.
  If a derivation is the input to, and therefore an element in the domain of, a <code>build</code> function, the input hash is a lookup key, which identifies this element and can therfore be used to store and look up build outputs or their content hashes. All derivations in Nix have an input hash, even CA derivations.</dd>
  <dt>unresolved input hash</dt>
  <dd>A type of input hash which is constructed from the set of inputs recursively, so that reflects the bitwise identity of only the leaves in the dependency tree in question, and the <em>build recipe</em> identity of how they are put together. This is called a deep constructive trace up to terminal inputs in the build systems a la carte paper, and my first paper. In Nix it is the hash that is part of the store path of any regular (input-addressed derivation). It is why they are called input-addressed.</dd>
  <dt>resolved input hash</dt>
  <dd>A type of input hash which is constructed from the set of inputs and incorporates identity of all direct dependencies by a content hash. This is called a constructive trace in the build systems a la carte paper, and my first paper. In Nix it is the hash of a resolved content-addressed derivation. The derivation itself is still input-addressed, and it has an input hash, but the individual inputs that factor into that hash are direct dependencies that are included with their content hash.</dd>
  <dt>IA derivation</dt>
  <dd>A regular derivation in Nix is called input-addressed (IA), because it's path contains an unresolved input hash. This path containing the unresolved input hash is the lookup key to find the output of the derivation in the store. This means we look up o = build(unresolved_ia_i) in the store directly by accessing <code>/nix/store/{path(unresolved_ia_i, drv_output)}</code>, which contains <code>build(unresolved_ia_i)</code></dd>
  <dt>CA derivation</dt>
  <dd>A content-addressed (CA) derivation uses the <code>ca-derivations</code> feature in Nix. Before building it does dependency resolution on the unresolved CA derivation, to obtain a resolved CA derivation. The input hash of the resolved CA derivation becomes the lookup key to find the output of the derivation outside the store. We look up <code>o = build(resolved_ca_i)</code> outside the store. Since the store is content-addressed, we then find the output in the store by looking up the output path <code>/nix/store/{content_hash(o)}-{name(o)}</code>, which contains <code>o</code>. CA derivations are sometimes called floating CA derivations to distinguish them from FODs.</dd>
  <dt>leaves / leaf nodes</dt>
  <dd>The outer nodes of any dependency tree might be things like sources files, or binary blobs. We call them leaves or leaf nodes, the build systems a la carte paper calls them terminal inputs.</dd>
  <dt>FOD / FO derivation</dt>
  <dd>FODs are a different kind of content-addressed derivation, which nix has supported for a long time. They pre-declare the hash of their outputs, which means their output paths can be pre-computed, even though they are content-addressed. When we use the term CA derivation, we do not include FODs. In our work FODs are considered content-addressed leaves, aka terminal inputs, in the dependency tree.</dd>
  <dt>IA path</dt>
  <dd>The output path of an IA derivation.</dd>
  <dt>CA path</dt>
  <dd>The output path a CA derivation or FOD.</dd>
  <dt>build trace</dt>
  <dd>A statement which associates the resolved input hash of a derivation with the output hashes of the set of produced output.</dd>
  <dt>provenance log entry</dt>
  <dd>A cyptograpically secured statement which associates the resolved input hash of a derivation with the output hashes of the set of produced output, and an open set of additional metadata about the builder.
  This potentially includes a source reference for the builders claimed software state and maybe even a remote attestation of said software state.
  This statement might be sigend, or be entered in a transparency log.</dd>
  <dt>nix legacy signature</dt>
  <dd>A statement which associates the unresolved input hash of a derivation with the output hash of a specific produced output. This does not contain any data about the builder, and depends on all of those implicit dependency resolutions that happen with IA derivations, because it uses an unresolved input hash. I'm calling it legacy because we are trying to replace it as the load-bearing component in terms of trust.</dd>
  <dt>laut signature</dt>
  <dd>A signature in the format specified in this repository.</dd>
  <dt>trustlessly-resolved derivation</dt>
  <dd>We call a derivation, for which the validator resolves all dependencies and then looks up build traces trustlessly resolved.</dd>
  <dt>trustfully-resolved derivation</dt>
  <dd>We call a derivation, for which the validator looks up a legacy signature and thereby trusts however its builder resolved its immediate dependencies trustfully resolved.</dd>
  <dt>trust model</dt>
  <dd>A set of trusted keys and additional, per key, validation criteria which must be met to consider a provenance log entry or nix legacy signature valid.</dd>
  <dt>threshold function</dt>
  <dd>The way trust models are constructed from trusted keys is using a threshold function. <code>threshold(m, n = len(keys), keys: set)</code>, where only the mapping from inputs to outputs are considered trustworthy, which m out of n keys agree on. This is used to build OR and AND functions. We actually also not only allow keys as input to the threshold function, but also trust models, which allows for more complex trust model, but also makes the definition of trust model recursive.</dd>
  <dt>builder</dt>
  <dd>A verifier of the inputs to its own builds, as well as a a signer of the outputs of its own builds.</dd>
  <dt>signer / producer</dt>
  <dd>A builder, which produces signatures they have built themselves, and potentially uploads  them to a cache.</dd>
  <dt>verifier / consumer</dt>
  <dd>A consumer (and verifier according to some trust model) of signatures, and possibly also build outputs, from a cache.</dd>
  <dt>legacy signer</dt>
  <dd>A builder or INTERMEDIARY, producing signatuers. While addressing this problem is out of scope for laut, signing intermediaries introduce transitive trust relationships that are difficult to revoke, which is why we think groups of builders should be organized around data structures like signed lists or transparency logs instead.</dd>
</dl>

[^1]: according to https://en.langenscheidt.com/german-english/laut 📖
[^2]: set of trusted builders with additional constraining criteria, including consensus
