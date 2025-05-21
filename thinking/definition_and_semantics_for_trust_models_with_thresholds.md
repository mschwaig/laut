# Recursive definition of trust models with thresholds


## Preliminaries

Assume we have a function called build() which transforms a set of inputs into an output.

The domain of the build afunction is the set of inputs of the build step.
The co-domain of the build function is a build output.

Both sets of inputs and build outputs can be referred to by a characteristic hash value.
For input sets these are called input hashes, for outputs they are called content hashes.

There is both an abstract and a concrete way of defining dependency trees this way.
We can generate the abstract description by defining input sets via recursion in the domain of the build function.
In practice this means input sets contain hashes of other input sets they depend on.
This is called an unresovled input hash.

Once we start building, we can instead construct an input set from the co-domain, in practice this means content hashes of already built outputs.
This is called a resolved input hash.
The link from the resolved input set of a build step to its output is called a build trace. A verifier need evidence of this operation, because it is costly, complex and potentially non-deterministic.
The link between a build output and the input hash of the build step immediately downstream from it is constructed by inclusion in this hash. A verifier can do the hashing required for this themselves, so we don't need to involve a third party in the same way. 

## Goal

Given a dependency tree defined in terms of unresolved input hashes, our goal is to find a more specific dependency tree in terms of resolved input hashes of inputs and content hashes of output, so that each link in the tree can be verified to satisfy a set of criteria.

## Some Examples

In simple cases, these criteria are stated in terms of signatures, which associate the resolved input hash of a build step with the content hash of its output.
If we have such evidence for each node in the tree, and they all link up, we have verified that the final output was produced from the leaf inputs.

We want to support more complex ways of modeling trust however, where a set containing a mix of keys and trust models is paired with a numerical threshold value >= 1, to make up a trust model. This recursive definition allows us to state complex validation criteria about each link in a specific dependency tree.
Both keys and trust models are identified by color in this description.

When the threshold value is 1, this means when constructing our tree, we accept build traces signed with either one of the set members.

Threshold values of 2 and above can only be achieved when the whole dependency tree behaves like one big reproducible build step.
Interestingly this does not mean that each build step involved has to be reproducible.
The fist build step can introduce some entropy which is passed down until the final build step, where it gets removed by not having an effect on the final output,
meaning the two ways of producing the final output look totally divergent until the final build step.

## Trying to define semantics

It is difficult to define proper semantics for these threshold-function based trust models, so we will do it in a very particular way here, that we hope is actually well-behaved and does not have a bunch of loose ends we forgot about.

Instead of considering the whole graph right away we will consider only how one specific leaf input contributes to the final output, by introducing the concept of
a thread, which is a chain starting with the content hash of a leaf in the dependency tree,
and including in an alternating manner a resolved input hash, and its output, until finally terminating with the content hash of the final output.

A thread is an object which lives in the domain defined by one specific abstract / unresolved dependency tree.
Threads are composable, if the verifier can produce them by performing dependency resolution on the same unresolved dependency tree, and they do not violate any of the given constraints.

* Each link in a thread has to have a color that is valid in the trust model under consideration on the relevant level.
* Two links from two threads at the position of the same unresolved input hash, may only have the same color, if they do not start at the same leaf.
* Each thread terminates at the same final output.

We can verify a dependency tree in accordance with an arbitrary trust model, by composing threads while respecting the above two constraints.
Composition can lead into dead ends, but for trees that are valid in accordance with the trust model there should be some composition, that is not a dead end.

Verification is successful once we can count threshold threads beginning at each leaf input of the unresolved dependency tree,
at which point threshold * count(leaf input) threads will also terminate at the final output.

One thing we need from such a definition is that we can apply it recursively, meaning we can use it at each level / in each composite part of the trust model, and still get sane semantics.

## Illustrative Thoughts on Recursion and Composition 

The ground of these thoughts is less sound, and I am talking about a bunch of stuff that I am not defining properly, but I hope it is clear what properties and desired semantics I am getting at.

We can take some scissors, and cut our resolved dependency tree into two pieces in arbitrary ways, or even cut a hole in it, and the pieces that we are left with still "make sense".
Both pieces may become forests, with the additional constraint or effect that "outgoing" links become final outputs and "incoming links" become leaves.
Any arbitrary re-coloring of the same links which satisfies our constraints and the trust model will work interchangeably if put the original tree back together after repainting it.

To be more specific there are two ways of dealing with those pieces, which tells us different things:

1. Option: We can accept that the threshold has to be met at every point where we make the cut, and have each piece be defined in the same two unresolved forests with known target outputs, that compose back to the same unresolved forest.
2. Option: We can recursively accept that the set of introduced extra inputs and outputs does not have to meet the threshold and be the same, and we end up with a collection of forests that are defined in terms of different unresolved trees, but nonetheless compose nicely back into the same resolved one.

The first decomposition places an emphasis on the fact that any subset of the same trust model which meets the threshold is interchangeable, but its structurally different constituents are not.
The second decomposition places an emphasis on the fact that any structurally equal subset of constituents of a trust model with an associated fixed set of counts per specific output / input is interchangeable.

But the repainting argument applies to both kinds of decomposition.
We can repaint and validate each of those trees independently, and then put them together to form one big valid tree.

Form the second decomposition we get a description of how at any point in the tree if we can stick with structurally equal set of constituents to determine validity, convergence at the link in question is not necessary.
What we get from the first decomposition is a description of how at any point of the tree we can move from one subset of constituents of the trust model determining validity, to another (structurally different) set of constituents determining validity, as long as there is convergence to one output at the point in question.

