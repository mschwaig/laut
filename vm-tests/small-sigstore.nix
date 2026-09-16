{ pkgs, system, laut, laut-sign-only }:
let
  tools = pkgs.callPackage ../nix/rekor-test-tools.nix { };
  python = pkgs.python3.withPackages (p: [ p.cryptography ]);
  logMaterial = pkgs.runCommand "laut-public-test-log-keys" { nativeBuildInputs = [ python ]; } ''
    python ${./make-log-test-root.py} $out
  '';
  # Opaque store-path context deliberately makes busybox an input source,
  # not an unsigned derivation dependency. Both tiny builds are self-contained.
  expression = ca: pkgs.writeText "small-sigstore-${if ca then "ca" else "ia"}.nix" ''
    let shell = builtins.storePath "${pkgs.busybox}"; in
    derivation {
      name = "laut-small-${if ca then "ca" else "ia"}";
      system = "${system}";
      builder = "''${shell}/bin/sh";
      outputs = [ "out" "dev" ];
      args = [ "-c" "''${shell}/bin/mkdir -p $out $dev; echo result > $out/result; echo header > $dev/header" ];
      ${pkgs.lib.optionalString ca ''
        __contentAddressed = true;
        outputHashMode = "recursive";
        outputHashAlgo = "sha256";
      ''}
    }
  '';
  defaults = {
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
    nix.settings = {
      experimental-features = [ "nix-command" "ca-derivations" ];
      substituters = pkgs.lib.mkForce [ ];
    };
    environment.etc = {
      "sigstore/log-root.json".source = "${logMaterial}/log-root.json";
      "sigstore/wrong-log-root.json".source = "${logMaterial}/wrong-log-root.json";
      "small-ca.nix".source = expression true;
      "small-ia.nix".source = expression false;
      "nix/test-public-key".source = ../testkeys/builderA_key.public;
    };
    environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.jq ];
  };
  cache = import ./machines/cache.nix {
    inherit pkgs system;
    inherit (pkgs) lib;
    cachePort = 9000;
    cacheStoreUrl = "http://cache:9000";
  };
  testLib = import (pkgs.path + "/nixos/lib/testing-python.nix") { inherit system; };
  sign = testLib.runTest {
    name = "laut-small-sigstore-sign";
    inherit defaults;
    nodes = {
      inherit cache;
      rekor = {
        networking.firewall.allowedTCPPorts = [ 80 ];
        systemd.services.rekor = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            StateDirectory = "rekor";
            ExecStart = "${tools}/bin/rekor-server serve --hostname=rekor --http-port=80 --http-address=0.0.0.0 --storage-dir=/var/lib/rekor --signer-filepath=${logMaterial}/log.pem --checkpoint-interval=100ms --batch-max-age=10ms";
          };
        };
      };
      builder = {
        environment.systemPackages = [ laut-sign-only tools ];
        environment.etc."nix/test-key".source = ../testkeys/builderA_key.private;
        nix.settings.post-build-hook = pkgs.writeShellScript "laut-logged-hook" ''
          set -eu
          ${laut-sign-only}/bin/laut sign-and-upload "$DRV_PATH" \
            --secret-key-file /etc/nix/test-key --to http://cache:9000 \
            --rekor http://rekor --trusted-root /etc/sigstore/log-root.json --include-preimage
          ${pkgs.nix}/bin/nix copy --to http://cache:9000 --no-check-sigs $OUT_PATHS
        '';
      };
    };
    testScript = ''
      import base64
      import json
      import shlex

      start_all()
      rekor.wait_for_unit("rekor.service")
      rekor.wait_for_open_port(80)
      cache.wait_for_unit("http-cache-server.service")
      cache.wait_for_open_port(9000)
      builder.wait_for_unit("multi-user.target")
      cache.succeed("mkdir -p /var/lib/cache/traces; printf 'StoreDir: /nix/store\\nWantMassQuery: 0\\n' > /var/lib/cache/nix-cache-info")
      # The network restriction applies to the runtime, not source fetching
      # while Nix constructs the test closure.
      builder.fail("curl --connect-timeout 1 --max-time 2 http://192.0.2.1")
      for regime in ["ca", "ia"]:
          builder.succeed(f"nix-build /etc/small-{regime}.nix --no-out-link --no-substitute > /tmp/{regime}-outputs")
      drv = builder.succeed("nix-instantiate /etc/small-ca.nix").strip()
      outputs = " ".join(builder.succeed(f"nix path-info '{drv}^*'").split())
      builder.succeed(f"laut sign {drv} --out-paths '{outputs}' --secret-key-file /etc/nix/test-key > /tmp/direct.json")
      builder.succeed("laut-interop /etc/sigstore/log-root.json /tmp/direct.json ${../testkeys/builderA_key.public} direct")
      builder.fail("laut-interop /etc/sigstore/log-root.json /tmp/direct.json ${../testkeys/builderA_key.public} logged")
      recorded = json.loads(cache.succeed("cat /var/lib/cache/traces/*").splitlines()[0])
      direct = dict(recorded)
      direct["verificationMaterial"] = {"publicKey": recorded["verificationMaterial"]["publicKey"]}
      wire_bytes = lambda value: len(json.dumps(value, separators=(",", ":")).encode())
      print("sample bundle bytes (with debug preimage):", wire_bytes(recorded))
      print("sample transparency material overhead bytes:", wire_bytes(recorded) - wire_bytes(direct))
      entry = recorded["verificationMaterial"]["tlogEntries"][0]
      metadata = json.loads(base64.b64decode(entry["canonicalizedBody"]))["spec"]["hashedRekordV002"]
      request = json.dumps({"hashedRekordRequestV002": {"digest": metadata["data"]["digest"], "signature": metadata["signature"]}})
      status = cache.succeed("curl -sS -o /tmp/duplicate-response -w '%{http_code}' -H 'Content-Type: application/json' --data " + shlex.quote(request) + " http://rekor/api/v2/log/entries")
      assert status == "409", status
      # Stopping the log must not silently turn logged publication into direct.
      before = cache.succeed("sha256sum /var/lib/cache/traces/*")
      rekor.succeed("systemctl stop rekor.service")
      builder.fail(f"laut sign-and-upload {drv} --out-paths '{outputs}' --secret-key-file /etc/nix/test-key --to http://cache:9000 --rekor http://rekor --trusted-root /etc/sigstore/log-root.json")
      assert before == cache.succeed("sha256sum /var/lib/cache/traces/*")
      cache.copy_from_vm("/var/lib/cache", "")
    '';
  };
  verify = testLib.runTest {
    name = "laut-small-sigstore-verify";
    inherit defaults;
    nodes = {
      cache = cache // {
        environment.etc."mutate-bundles.py".source = ./mutate-bundles.py;
        environment.etc."tamper-preimage.py".source = ./tamper-preimage.py;
      };
      verifier.environment.systemPackages = [ laut tools ];
    };
    testScript = ''
      start_all()
      cache.wait_for_unit("http-cache-server.service")
      cache.succeed("systemctl stop http-cache-server.service")
      cache.copy_from_host("${sign}/cache", "/var/lib")
      cache.succeed("chmod -R u+w /var/lib/cache; cp -r /var/lib/cache/traces /var/lib/original-traces; systemctl start http-cache-server.service")
      cache.wait_for_open_port(9000)
      verifier.wait_for_unit("multi-user.target")
      verifier.fail("curl --connect-timeout 1 --max-time 2 http://192.0.2.1")
      targets = [verifier.succeed(f"nix-instantiate /etc/small-{r}.nix").strip() for r in ["ca", "ia"]]
      verifier.succeed(f"nix copy --from http://cache:9000 --no-check-sigs $(nix-store -q --outputs {targets[1]})")
      base = "laut verify --cache http://cache:9000 --trusted-key ${../testkeys/builderA_key.public}"
      logged = base + " --require-log --trusted-root /etc/sigstore/log-root.json"
      for drv in targets:
          verifier.succeed(f"{logged} {drv}")
      # No log node exists in this test. Independently verify every bundle.
      hashes = cache.succeed("ls /var/lib/cache/traces").split()
      for h in hashes:
          verifier.succeed(f"curl -fsS http://cache:9000/traces/{h} -o /tmp/bundle.jsonl")
          verifier.succeed("laut-interop /etc/sigstore/log-root.json /tmp/bundle.jsonl ${../testkeys/builderA_key.public} logged")
      verifier.fail(f"{base} --require-log --trusted-root /etc/sigstore/wrong-log-root.json {targets[0]}")
      for mutation in ["strip", "payload", "signature", "checkpoint", "proof", "index", "binding", "verifier"]:
          cache.succeed("cp /var/lib/original-traces/* /var/lib/cache/traces/")
          cache.succeed(f"python3 /etc/mutate-bundles.py /var/lib/cache/traces {mutation}")
          for drv in targets:
              status, output = verifier.execute(f"{logged} {drv}")
              assert status == 118, (mutation, status, output)
          if mutation == "strip":
              for drv in targets:
                  verifier.succeed(f"{base} {drv}")
      cache.succeed("cp /var/lib/original-traces/* /var/lib/cache/traces/")
      marker = "LAUT_SIGSTORE_PREIMAGE_TAMPER"
      cache.succeed(f"python3 /etc/tamper-preimage.py /var/lib/cache/traces {marker}")
      failures = 0
      for drv in targets:
          status, output = verifier.execute(f"{logged} --debug-preimage-corpus http://cache:9000 --debug-out-dir /tmp/probe {drv} 2>&1")
          if status == 118:
              failures += 1
              assert marker in output, output
          else:
              assert status == 0, output
      assert failures == 1
      cache.succeed("cp /var/lib/original-traces/* /var/lib/cache/traces/")
      verifier.succeed(f"{logged} {targets[0]}")
    '';
  };
in { inherit sign verify; }
