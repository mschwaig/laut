{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs { },
}:

pkgs.lib.makeScope pkgs.newScope (self: {
  laut = self.callPackage ./nix/laut.nix { };
  laut-sign-only = self.callPackage ./nix/laut.nix { sign-only = true; };
})
