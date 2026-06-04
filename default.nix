{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs { },
}:

# TODO: verify that laut works without applying
# github:mschwaig/nixpkgs/fix-swig-option-for-souffle-before-rebase
pkgs.lib.makeScope pkgs.python3Packages.newScope (self: {
  laut = self.callPackage ./nix/laut.nix { };
  laut-sign-only = self.laut.override {
    sign-only = true;
    lautr = self.lautr-sign-only;
  };
  lautr = self.callPackage ./nix/lautr.nix { };
  lautr-sign-only = self.callPackage ./nix/lautr.nix { sign-only = true; };
})
