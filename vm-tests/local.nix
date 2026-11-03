# Tests local signing with default settings. The host enables only
# services.laut.sign and services.laut.verify, signs its own CA builds into
# /var/lib/laut, and verifies them against its own key.
{
  system,
  pkgs,
  laut,
  laut-sign-only,
  nixPackage,
  ...
}:
let
  testLib = import (pkgs.path + "/nixos/lib/testing-python.nix") { inherit system; };
in
testLib.runTest {
  name = "laut-local-ca";

  nodes.machine = {
    imports = [ ../nixos ];

    services.laut.sign = {
      enable = true;
      package = laut-sign-only;
    };
    services.laut.verify = {
      enable = true;
      package = laut;
    };

    nix = {
      package = nixPackage;
      settings.experimental-features = [ "nix-command" "ca-derivations" ];
    };

    # Two CA derivations. b reads a's output, so verifying b has to resolve a.
    # The builders use only shell builtins, so they need nothing beyond the
    # sandbox's /bin/sh.
    environment.etc."laut-chain.nix".text = ''
      let
        mk = name: script: derivation {
          inherit name;
          system = builtins.currentSystem;
          builder = "/bin/sh";
          args = [ "-c" script ];
          __contentAddressed = true;
          outputHashMode = "recursive";
          outputHashAlgo = "sha256";
        };
      in rec {
        a = mk "laut-local-a" "echo a > $out";
        b = mk "laut-local-b" "read x < ''${a}; echo \"$x b\" > $out";
      }
    '';
  };

  testScript = ''
    import json

    traces = "/var/lib/laut/traces"
    chain = "/etc/laut-chain.nix"

    machine.wait_for_file("/var/lib/laut/local.key.public")
    assert machine.succeed("stat -c %a /var/lib/laut/local.key").strip() == "600"

    # a has no input derivations, so building it writes exactly one trace.
    machine.succeed(f"nix-build {chain} -A a --no-out-link")
    a_names = machine.succeed(f"ls {traces}").split()
    assert len(a_names) == 1, a_names
    a_trace = f"{traces}/{a_names[0]}"

    machine.succeed(f"nix-build {chain} -A b --no-out-link")
    b_drv = machine.succeed(f"nix-instantiate {chain} -A b").strip()
    machine.succeed(f"laut verify {b_drv}")

    def flip_signature(jws):
        signing_input, sig = jws.rsplit(".", 1)
        return f"{signing_input}.{'B' if sig[0] == 'A' else 'A'}{sig[1:]}"

    body = json.loads(machine.succeed(f"cat {a_trace}"))
    body["signatures"] = [flip_signature(s) for s in body["signatures"]]
    machine.succeed(f"echo '{json.dumps(body)}' > {a_trace}")

    # With a's signatures broken, b no longer resolves. laut must report that
    # as a failed verification (exit 118), not as an error (exit 1).
    status, out = machine.execute(f"laut verify {b_drv} 2>&1")
    assert status == 118, f"expected exit 118, got {status}:\n{out}"
  '';
}
