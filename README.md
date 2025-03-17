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
* like realizations for CA derivations, but also works for IA derivations
* based on a new proposed signature format on top of JWS, with
* arbitrary additional but detachable metadata
* integrates with/extends https://github.com/nikstur/bombon to create verifiable SBOMs

Right now it can't even verify `github:mschwaig/nixpkgs-ca#hello` yet! 😓

I want to get a scientific paper, and later my PhD thesis published based on this work, so if you do something that's inspired by this project, please give me a shoutout in your README.md, your docs or the relevant issue in your issue tracker. This really helps me demonstrate that my work is relevant for somebody.

### How can I use it

This is a standalone command line tool called `laut`[^3],  which has two subcommands:

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
This command tries to verify that a given derivation is valid according to the stricter validation criteria of the tool. Later on there will be more options to configure a specific trust model to verify against, and you will be able to additionally pass an SBOM which then also has to match the other elements.

### How does it work

It's a python program. The signing is very straighforward python code.

The verification is more complicated, as it instantiates an actual dependency tree in memory, then walks through that tree and emits facts about the dependency tree to some files.
These files then serve as the input to a datalog program using SWIG, to make the actual determination about the validity of the dependency tree.

The datalog program is compiled using souffle inside of its own derivation.

### How can I test it

As of now, there are two kinds of tests in this project

The python tests, which can be run with

```
pytest -s tests/
```

inside a nix develop shell, and the NixOS VM tests, which you can run by first buliding the test driver for one of the tests
```
nix build .#checks.x86_64-linux.fullReproVM.driverInteractive 
```

and then running the resulting binary to get into this emacs shell.

In that shell you can then run the test using the "test_script()" function.

**In the future** each VM test should validate according to a different trust model, but right now there is no meaningful distinction between them yet.

We can also test our reasoning about trust relationships directly in datalog, in a another set of tests.

### FAQ

**Q:** Do you want to upstram this?  
**A:** Yes. With this project, I want to lead a credible effort to propose a specific signaure format, which does what I want from such a format, as outlined in my paper.

**Q:** Do you accept contributions?  
**A:** Yes, I am enthusiastic about collaborating on this, and helping people with getting started on that. I also want to reply to proposals and criticism within a week. If I don't and you're waiting on an answer from me, please remind me.

**Q:** What do you want from a signature format in Nix?  
**A:** To turn Nix into a leading edge supply chain security tool. Nix has interesting properties in that area, but it is not living up to its potential yet.

**Q:** Are you interested in working with different implementations of Nix?  
**A:** Yes, definitely. I feel like a flexible enough signature format can be especially useful in an increasingly diverse ecosystem. Let's make it possible to let Nix evolve over time, try new ideas, AND interoperate as much as possible while doing it. It's important to me to have a good working relationship with others in the community across various implementations of Nix, who care about these issues as well.
  Please open issues, reach me on matrix or via email at m@groundry.org.

**Q:** Why are you not implementing this in Nix or any of its implementations directly?  
**A:** Eventually that is definitely the way you would want to do this kind of thing, but for now it is meant to prove the concept (also across implementations) and introduce it to an expert audience, with a lot of breakage much shorter iterat ion times.

**Q:** Can I use this now?  
**A:** No, it does not do anything useful yet, but you can help work on it.

### Glossary

I think having a bunch of important terms explaind here will be useful.

[^1]: according to https://en.langenscheidt.com/german-english/laut 📖
[^2]: set of trusted builders with additional constraining criteria, including consensus
[^3]: as of now the binary is still called `trace-signatures` since I only came up with the name a few days ago
