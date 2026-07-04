## laut /laʊt/ - distributed trust and verifiable provenance data for Nix

The name is german for[^1]
* loud, noisy, blatant 📢
* (as) per, according to, in accordance with 🕵️‍♀️

<div align="center">

---

🚧 This is an in-progress implementation of https://dl.acm.org/doi/10.1145/3689944.3696169. 🚧

---

</div>

Build results in Nix today can travel from builder to cache to user, "trusted"
along the way but not attributed to whoever actually produced them — like a
game of telephone. `laut` is a standalone tool that ships as a secondary
binary alongside Nix and is more pedantic about where things come from. Each
claim about a build is signed by whoever made it and is designed to be precise
enough that `laut` can aggregate signatures from original sources rather than
from whichever cache a result happened to pass through. This lets you pick who
you trust independently from everyone else and change your mind about it over
time.

The fundamentals are in place, with a few things still needing work (marked ❎):
* configurable trust model[^2] ✅, ...
* which can be re-configured over time, ✅ based on ...
* verifiable provenance data for builders ❎
* like realizations for CA derivations ✅, and also for IA derivations ✅
* based on a new proposed signature format on top of JWS ✅, with
* arbitrary additional ✅ but detachable ❎ metadata

Right now `laut` can resolve the dependencies for and verify a fully
content-addressing or input-addressing `hello` binary, end to end, in our VM
tests. The implementation is approaching a state where it is ready for its
first users; until then expect breakage and short iteration times. As a
project we are also not yet committed to supporting the current shape of the
signatures long term — the envelope format and a few payload fields may still
change. More paranoid features (provenance transparency log entries, remote
attestation, sigstore-style integration) are on the horizon, and the dream is
to get the signatures (or log entries) widely available, e.g. via the NixOS
Hydra instance.

If you do something that's inspired by this project, please give me a
shoutout — it helps me demonstrate the relevance of this work in an academic
context.

### How can I use it

`laut` ships as two things: a CLI tool and a NixOS module.

#### NixOS module

The NixOS module is the primary interface. Add the flake to your system
inputs and import the module:

```nix
{
  inputs.laut.url = "github:mschwaig/laut";
  outputs = { self, nixpkgs, laut, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        laut.nixosModules.laut
        # ...
      ];
    };
  };
}
```

**Signing** (`services.laut.sign`): installs `laut` on a builder and
wires the Nix `post-build-hook` to upload signed traces + store paths
to your cache:

```nix
services.laut.sign = {
  enable = true;
  cacheUrl = "http://cache.example.org:9000";
  secretKeyFile = "/etc/laut/builder.key";
  publicKeyFile = "/etc/laut/builder.key.public";
  includePreimage = false;  # set true for debug caches only
};
```

**Verification** (`services.laut.verify`): installs `laut` and provides a
`laut-verify` wrapper pre-configured with your caches and trust model. Users
run `laut-verify <drv>` without any additional flags:

```nix
services.laut.verify = {
  enable = true;
  caches = [ "http://cache.example.org:9000" ];
  trustModel = {
    threshold = 2;
    of = [
      { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
      { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
    ];
  };
};
```

#### Trust models

The trust model is a recursive structure with two node kinds:

- `key` — a leaf naming a single trusted signing key, as a
  `name:base64-public-key` string (the same format Nix uses for
  `trusted-public-keys`).
- `{ threshold, of }` — `threshold` of the `of` sub-models must be satisfied.
  Children may themselves be `key` leaves or further thresholds.

Some canonical shapes:

```nix
# Self-build only — trust only your own key
{ key = "self:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }

# Reproducibility, 2-of-2 — both builders must agree
{ threshold = 2; of = [
    { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
    { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
  ];
}

# Any one of these signers suffices
{ threshold = 1; of = [
    { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
    { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
  ];
}

# Nested: I built it AND at least one trusted cache agrees
{ threshold = 2; of = [
    { key = "self:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
    { threshold = 1; of = [
        { key = "cacheA:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="; }
        { key = "cacheB:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="; }
      ];
    }
  ];
}

# Legacy cache fallback: trust a cache's word OR require the stricter model
{ threshold = 1; of = [
    { key_legacy = "cache:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
    { threshold = 2; of = [
        { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
        { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
      ];
    }
  ];
}
```

`key_legacy` marks a key that short-circuits upstream verification at the
point where it signs — useful for trusting an existing cache "as-is". It is
only permitted as a direct child of a top-level `threshold = 1` (an OR at the
root of the model).

The verification semantics are defined in
[docs/semantics.md](docs/semantics.md).

#### CLI

The CLI is the low-level interface; the NixOS module wraps it.

Signing (from a post-build hook):
```
laut sign-and-upload --to [HTTP cache URL] --secret-key-file [KEY] [DRV_PATH]
```
Exit codes: `0` = signed and uploaded, `117` = no-op (hook fired on
unresolved drv or FOD), `1` = error. `$OUT_PATHS` supplies output paths.

Verification:
```
laut verify --cache [URL] --trust-model-config [PATH TO NIX FILE] [DRV_PATH or flake ref]
```
The `--trust-model-config` flag points at a `.nix` file that evaluates to the
trust model attrset shown above. The `LAUT_TRUST_MODEL_CONFIG` environment
variable is an alternative to the flag — this is how the NixOS module's
`laut-verify` wrapper pre-configures it.

### How does it work

It's a Rust workspace (`laut-cli` for argument parsing and dispatch,
`laut-sign` for sign-side orchestration and the shared core, and
`laut-verify` for verification). The hashing schemes and ATerm / castore
encoding come from `nix-compat` / `laut-compat` on the
`mschwaig/snix#fanfic` branch, and the signature envelope is JWS-based.
NixOS modules under `nixos/` wrap the CLI for end-user deployment.

The signing side is straightforward: it walks the derivation, computes the
resolved input hash, gathers output content hashes, and assembles a signed
JWS token. Both content-addressed and input-addressed derivations are
supported — for IA derivations the signer walks the runtime closure to
substitute synthetic CA paths and computes the CA-equivalent resolved input
hash.

The verification is more complicated, as it instantiates an actual dependency
tree in memory, then walks through that tree to gather information. As part of
this verification phase, the tool also gathers signatures from a set of
caches, taking into account possible combinations of inputs by content hash,
which could satisfy the dependency on those same inputs by input hash. This
data then feeds into a verifier that decides whether the configured trust
model is satisfied. The verification semantics are defined in
[docs/semantics.md](docs/semantics.md).

### How can I test it

There are Rust unit tests (next to the code) and integration tests, runnable
inside a `nix develop` shell with
```
cargo test --workspace
```

plus NixOS VM tests that exercise the end-to-end signer + verifier flow.
Build a test driver with, for example,
```
nix build .#checks.x86_64-linux.small-ca-sign.driverInteractive
```
then run the resulting binary and call `test_script()` inside the driver
shell. The VM tests come in `{small,medium,large} × {ca,ia}` flavors (the IA
flavors currently exist as red baselines until IA support is wired up
end-to-end).

The VM tests use the NixOS module with a `threshold(2, [builderA, builderB])`
trust model — both builders must sign every build step.

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
**A:** The implementation is approaching a point where it is ready for its first users, and the VM tests already verify a full CA or IA `hello` end to end. Until it lands there, expect breakage and short iteration times, and treat the current signature shape as not yet final. If you want to help shape it, now is a good time to get involved.

### Glossary

Here is a list of technical terms we use in this project with their definitions:

<dl>
  <dt>derivation / drv</dt>
  <dd>Nix uses this term for build steps, which are identified and defined by their characteristic input hash. In this project we will define a derivation strictly as an element <code>i</code> in the domain of a function <code>build(i: input) -> output</code> and not as the pair of both input output <code>(i, build(i))</code>.</dd>
  <dt>unresolved derivation / udrv</dt>
  <dd>A derivation, which depends on other derivations.</dd>
  <dt>resolved derivation / rdrv</dt>
  <dd>A derivation, which does not depend on other derivations (anymore). The content-addressed derivation RFC also calls this a basic derivation.</dd>
  <dt>derivation output / output path</dt>
  <dd>Each derivation can have more than one derivation output, which show up in the Nix store as/at separate output paths, but were created by building the same derivation. This step of indirection and distinction between individual outputs of a derivation is not an important concern when reasoning about trust, but it shows up in the technical details sometimes. Derivation outputs refers to the abstract names of these outputs, written as <code>/nix/store/{hash}-{name}.drv$out</code>, while output path refers to their "physical manifestation" in terms of a path / address and the contents of those outputs in the store, like <code>/nix/store/{hash}-{name}</code> and its content.</dd>
  <dt>content hash</dt>
  <dd>Describes the bitwise identity of a file or path by hashing it in a defined manner.</dd>
  <dt>output map</dt>
  <dd>A mapping from each <em>derivation output</em> name of a derivation to its corresponding <em>content hash</em>. Together with a <em>resolved input hash</em>, an output map describes one execution of <code>build</code>: the resolved input hash names the input set, and the output map names what was produced for each named output.</dd>
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
  <dt>build trace</dt>
  <dd>A statement which associates the resolved input hash of a derivation with the output hashes of the set of produced output.</dd>
  <dt>provenance log entry</dt>
  <dd>A cyptograpically secured statement which associates the resolved input hash of a derivation with the output hashes of the set of produced output, and an open set of additional metadata about the builder.</dd>
  <dt>nix legacy signature</dt>
  <dd>A statement which associates the unresolved input hash of a derivation with the output hash of a specific produced output. This does not contain any data about the builder, and depends on all of those implicit dependency resolutions that happen with IA derivations, because it uses an unresolved input hash. I'm calling it legacy because we are trying to replace it as the load-bearing component in terms of trust.</dd>
  <dt>laut signature</dt>
  <dd>A signature in the format specified in this repository.</dd>
  <dt>trust model</dt>
  <dd>A recursive structure of trusted keys and threshold functions which decides whether a set of signatures is sufficient. See the trust models section above for concrete examples, and [docs/semantics.md](docs/semantics.md) for the formal definition.</dd>
  <dt>legacy signer</dt>
  <dd>A key trusted "as-is" — its signature short-circuits upstream verification at the point where it signs. Declared via <code>key_legacy</code> in the trust model. Only permitted as a direct child of a top-level <code>threshold = 1</code>.</dd>
  <dt>builder</dt>
  <dd>A verifier of the inputs to its own builds, as well as a signer of the outputs of its own builds.</dd>
  <dt>signer / producer</dt>
  <dd>A builder which produces signatures for builds it did itself, and potentially uploads them to a cache.</dd>
  <dt>verifier / consumer</dt>
  <dd>A consumer (and verifier according to some trust model) of signatures, and possibly also build outputs, from a cache.</dd>
</dl>

[^1]: according to https://en.langenscheidt.com/german-english/laut 📖
[^2]: set of trusted builders with additional constraining criteria, including consensus
