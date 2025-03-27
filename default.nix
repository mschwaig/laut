{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs { },
}:

pkgs.lib.makeScope pkgs.python3Packages.newScope (self: {
  laut = self.callPackage ./package.nix { };
  laut-sign-only = self.laut.override { sign-only = true; };
})
