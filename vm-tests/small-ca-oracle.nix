{ pkgs, system, nixPackage, nixRevision, probe, patches ? [] }:
let
  expression = pkgs.writeText "ca-oracle.nix" ''
    { case }:
    let
      shell = builtins.storePath "${pkgs.busybox}";
      mk = name: script: derivation {
        inherit name;
        system = "${system}";
        __contentAddressed = true;
        builder = "''${shell}/bin/sh";
        args = [ "-ec" script ];
      };
      dep = mk "oracle-dependency-input" "printf dependency > $out";
      depTwo = mk "oracle-second-input" "printf second > $out";
      scripts = {
        plain = "printf plain > $out";
        self-once = "printf '%s' $h > $out";
        self-twice = "printf '%s--%s' $h $h > $out";
        zero-and-self = "{ ''${shell}/bin/dd if=/dev/zero bs=32 count=1; printf -- '--%s' $h; } > $out";
        chunked = "{ ''${shell}/bin/dd if=/dev/zero bs=65519 count=1; printf '%s' $h; ''${shell}/bin/dd if=/dev/zero bs=65521 count=1; printf '%s' $h; } > $out";
        symlink = "''${shell}/bin/mkdir $out; printf data > $out/target; ''${shell}/bin/ln -s $out/target $out/link";
        dependency = "printf '%s:%s' ''${dep} ''${depTwo} > $out";
      };
    in mk "oracle-''${case}" ("h=$(''${shell}/bin/basename $out | ''${shell}/bin/cut -c1-32); " + scripts.''${case})
  '';
  testLib = import (pkgs.path + "/nixos/lib/testing-python.nix") { inherit system; };
in testLib.runTest {
  name = "laut-small-ca-oracle";
  nodes.machine = {
    virtualisation = {
      memorySize = 2048;
      cores = 2;
      diskSize = 2048;
      restrictNetwork = true;
      writableStore = true;
      useNixStoreImage = true;
      mountHostNixStore = false;
      additionalPaths = [ pkgs.busybox ];
    };
    nix = {
      package = nixPackage;
      checkConfig = false;
      settings = {
        experimental-features = [ "nix-command" "ca-derivations" ];
        substituters = pkgs.lib.mkForce [];
        eval-cache = false;
      };
    };
    environment.systemPackages = [ pkgs.python3 probe ];
    environment.etc = {
      "ca-oracle.nix".source = expression;
      "ca-oracle.py".source = ./ca-oracle.py;
      "ca-oracle.json".text = builtins.toJSON {
        inherit nixRevision patches;
        nixPackage = toString nixPackage;
        probe = toString probe;
      };
    };
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    status, output = machine.execute("python3 /etc/ca-oracle.py /tmp/ca-oracle")
    print(output)
    machine.copy_from_vm("/tmp/ca-oracle", "")
    assert status == 0, "native CA / synthetic identity oracle failed; see ca-oracle/report.json"
  '';
}
