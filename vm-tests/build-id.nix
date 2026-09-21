{ pkgs, unpatchedSource, patchedSource }:
let
  # Exercise the pinned wrapper scripts, not the pinned bootstrap toolchain.
  wrapper = source: pkgs.callPackage (source + "/pkgs/build-support/bintools-wrapper") {
    inherit (pkgs) stdenvNoCC coreutils gnugrep expand-response-params;
    bintools = pkgs.binutils-unwrapped;
    libc = pkgs.stdenv.cc.libc;
    nativeTools = false;
    nativeLibc = false;
  };
  unpatched = wrapper unpatchedSource;
  patched = wrapper patchedSource;
in
pkgs.runCommand "laut-build-id" {
  nativeBuildInputs = [ pkgs.python3 pkgs.stdenv.cc ];
} ''
  mkdir -p "$out"
  python3 - <<'PY'
  import os
  from pathlib import Path
  import re
  import subprocess

  # No inherited compiler-wrapper flags or setup-hook state: both wrappers
  # receive the same environment and use the same underlying binutils/libc.
  env = {
      "PATH": os.environ["PATH"],
      "TMPDIR": os.environ["TMPDIR"],
      "LC_ALL": "C",
      "NIX_STORE": "/nix/store",
      "NIX_BUILD_ID_STYLE": "sha1",
      # Enable the host-role mapping of unsuffixed NIX_SET_BUILD_ID.
      "NIX_BINTOOLS_WRAPPER_TARGET_HOST_${unpatched.suffixSalt}": "1",
  }
  paths = ["/nix/store/" + c * 32 + "-input" for c in ("a", "b")]
  assert len(paths[0]) == len(paths[1])
  out = Path(os.environ["out"])

  # Keep the source filename identical so the negative control changes code,
  # rather than just an ELF file symbol.
  for value, obj in ((1, "input.o"), (2, "changed.o")):
      Path("input.c").write_text(f"int probe(void) {{ return {value}; }}\n")
      subprocess.run([
          "${pkgs.stdenv.cc}/bin/cc", "-fPIC", "-c", "input.c", "-o", obj,
      ], env=env, check=True)

  def link(wrapper, name, response, set_id=1, explicit=False,
           path=None, obj="input.o", relocatable=False):
      target = out / name
      args = [wrapper + "/bin/ld", "-r" if relocatable else "-shared"]
      if not relocatable:
          args += ["-soname", "libprobe.so", "-rpath", path]
      if explicit:
          args += ["--build-id=sha1"]
      subprocess.run(args + [obj, "-o", str(target)], env=env | {
          "NIX_SET_BUILD_ID": str(set_id),
          "NIX_LD_USE_RESPONSE_FILE": str(response),
      }, check=True)
      return target

  def build_id(target):
      notes = subprocess.check_output([
          "${pkgs.binutils-unwrapped}/bin/readelf", "-n", str(target),
      ], env=env, text=True)
      ids = re.findall(r"Build ID: (\S+)", notes)
      assert len(ids) <= 1, (target, notes)
      return ids[0] if ids else None

  def normalize(target, path):
      data = target.read_bytes()
      assert path.encode() in data, (target, "missing RPATH")
      dynamic = subprocess.check_output([
          "${pkgs.binutils-unwrapped}/bin/readelf", "-d", str(target),
      ], env=env, text=True)
      assert any(
          ("(RPATH)" in line or "(RUNPATH)" in line) and f"[{path}]" in line
          for line in dynamic.splitlines()
      ), (target, dynamic)
      return data.replace(path.encode(), paths[0].encode())

  for response in (0, 1):
      baseline = [link("${unpatched}", f"baseline-{response}-{i}.so",
                       response, path=path) for i, path in enumerate(paths)]
      ids = [build_id(target) for target in baseline]
      assert all(re.fullmatch(r"[0-9a-f]{40}", value or "") for value in ids), ids
      assert ids[0] != ids[1], ("baseline must expose address-dependent IDs", ids)
      assert normalize(baseline[0], paths[0]) != normalize(baseline[1], paths[1])

      for set_id in (0, 1):
          for explicit in (False, True):
              label = f"patched-{response}-{set_id}-{int(explicit)}"
              pair = [link("${patched}", f"{label}-{i}.so", response,
                           set_id, explicit, path) for i, path in enumerate(paths)]
              changed = link("${patched}", f"{label}-changed.so", response,
                             set_id, explicit, paths[1], obj="changed.o")
              assert all(build_id(target) is None for target in [*pair, changed]), label
              assert pair[0].read_bytes() != pair[1].read_bytes(), label
              canonical = normalize(pair[0], paths[0])
              assert canonical == normalize(pair[1], paths[1]), label
              assert canonical != normalize(changed, paths[1]), "code change was masked"
              if response:
                  normal = out / f"patched-0-{set_id}-{int(explicit)}-0.so"
                  assert pair[0].read_bytes() == normal.read_bytes(), label

      # The old wrapper skips automatic IDs for -r, but honors explicit IDs.
      for explicit in (False, True):
          baseline = link("${unpatched}", f"baseline-{response}-{int(explicit)}.o",
                          response, explicit=explicit, relocatable=True)
          value = build_id(baseline)
          assert (re.fullmatch(r"[0-9a-f]{40}", value or "") if explicit
                  else value is None), (baseline, value)
          for set_id in (0, 1):
              target = link("${patched}", f"patched-{response}-{set_id}-{int(explicit)}.o",
                            response, set_id, explicit, relocatable=True)
              assert build_id(target) is None, target

  # Deliberately no separate-debug hook test: without a 40-digit build ID,
  # the pinned hook skips extraction. Build-ID-based debug lookup is sacrificed.
  print("build-ID regression checks passed (normal, response-file, relocatable)")
  (out / "passed").touch()
  PY
''
