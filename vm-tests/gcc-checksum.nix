{ pkgs, patchedSource }:
let
  gccSource = (import patchedSource { system = pkgs.stdenv.hostPlatform.system; }).gcc.cc.src;
  capture = pkgs.callPackage (patchedSource + "/pkgs/development/compilers/gcc/common/checksum.nix") {
    langC = true;
    langCC = true;
  };
in
capture (pkgs.stdenv.mkDerivation {
  name = "laut-gcc-checksum";
  outputs = [ "out" ];
  nativeBuildInputs = [ pkgs.python3 pkgs.gnumake ];
  dontUnpack = true;
  dontConfigure = true;
  # Minimal copies of the pinned GCC recipes, including the bootstrap branch.
  prePatch = ''
    mkdir -p gcc/c gcc/cp
    python3 - <<'PY'
    from pathlib import Path
    for frontend, target, objects in (
        ("c", "cc1", "C_OBJS"), ("cp", "cc1plus", "CXX_OBJS"),
    ):
        extra = "$(CODYLIB) " if frontend == "cp" else ""
        Path(f"gcc/{frontend}/Make-lang.in").write_text(
            f"{target}-checksum.cc : build/genchecksum$(build_exeext) checksum-options \\\n"
            f"\t$({objects}) $(BACKEND) {extra}$(LIBDEPS)\n"
            "\tif [ -f ../stage_final ] \\\n"
            "\t   && cmp -s ../stage_current ../stage_final; then \\\n"
            f"\t  cp ../prev-gcc/{target}-checksum.cc {target}-checksum.cc; \\\n"
            "\telse \\\n"
            f"\t  build/genchecksum$(build_exeext) $({objects}) $(BACKEND) {extra}$(LIBDEPS) \\\n"
            f"\t    checksum-options > {target}-checksum.cc.tmp && \\\n"
            f"\t  $(srcdir)/../move-if-change {target}-checksum.cc.tmp {target}-checksum.cc; \\\n"
            "\tfi\n"
        )
    PY
  '';
  postPatch = ''
    touch previous-postPatch-ran
  '';
  buildPhase = ''
    # Use the infrastructure compiler, not a rebuild of the experimental GCC.
    mkdir -p generator/source generator/shim
    tar -xf ${gccSource} --strip-components=1 -C generator/source --wildcards \
      '*/gcc/genchecksum.cc' '*/libiberty/md5.c' \
      '*/include/md5.h' '*/include/ansidecl.h'
    python3 - <<'PY'
    import gzip
    import os
    from pathlib import Path
    import shutil
    import subprocess
    import tarfile
    import tempfile

    Path("generator/shim/bconfig.h").write_text(
        "#define STDC_HEADERS 1\n#define HAVE_SYS_TYPES_H 1\n#define HAVE_STDINT_H 1\n"
        "#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__\n#define WORDS_BIGENDIAN 1\n#endif\n"
    )
    Path("generator/shim/system.h").write_text(
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <errno.h>\n"
        "#define xstrerror strerror\n"
    )
    subprocess.run([
        "cc", "-O2", "-Igenerator/source/include", "-include", "generator/shim/bconfig.h",
        "-c", "generator/source/libiberty/md5.c", "-o", "generator/md5.o",
    ], check=True)
    subprocess.run([
        "c++", "-O2", "-Igenerator/shim", "-Igenerator/source/include",
        "generator/source/gcc/genchecksum.cc", "generator/md5.o", "-o", "generator/genchecksum",
    ], check=True)
    generator = str(Path("generator/genchecksum").resolve())

    # Debug-only store paths affect genchecksum even when stripped objects agree.
    Path("debug-source.c").write_text("int checksum_fixture(void) { return 42; }\n")
    debug_objects = []
    for letter in ("a", "b"):
        prefix = "/nix/store/" + letter * 32 + "-debug-source"
        obj = f"debug-{letter}.o"
        subprocess.run([
            "cc", "-g", f"-fdebug-prefix-map={Path.cwd()}={prefix}",
            "-c", "debug-source.c", "-o", obj,
        ], check=True)
        assert prefix.encode() in subprocess.check_output(["readelf", "--debug-dump=info", obj])
        debug_objects.append(obj)
    assert subprocess.check_output([generator, debug_objects[0]]) != subprocess.check_output([generator, debug_objects[1]])
    subprocess.run(["strip", "--strip-debug", *debug_objects], check=True)
    assert Path(debug_objects[0]).read_bytes() == Path(debug_objects[1]).read_bytes()
    assert subprocess.check_output([generator, debug_objects[0]]) == subprocess.check_output([generator, debug_objects[1]])
    Path("debug-source.c").write_text("int checksum_fixture(void) { return 43; }\n")
    subprocess.run(["cc", "-g", "-c", "debug-source.c", "-o", "changed.o"], check=True)
    subprocess.run(["strip", "--strip-debug", "changed.o"], check=True)
    assert subprocess.check_output([generator, debug_objects[0]]) != subprocess.check_output([generator, "changed.o"])

    assert Path("previous-postPatch-ran").exists()
    for frontend in ("c", "cp"):
        recipe = Path(f"gcc/{frontend}/Make-lang.in").read_text()
        assert recipe.count("capture-checksum.sh") == 1
        assert ": build/genchecksum$(build_exeext) checksum-options" in recipe

    Path("gcc/build").mkdir()
    Path("gcc/build/genchecksum").write_text(
        "#!${pkgs.runtimeShell}\n"
        "if [ -e fail ]; then exit 23; fi\n"
        f'exec "{generator}" "$@"\n'
    )
    Path("gcc/build/genchecksum").chmod(0o755)
    Path("move-if-change").write_text("#!${pkgs.runtimeShell}\nmv \"$1\" \"$2\"\n")
    Path("move-if-change").chmod(0o755)
    Path("gcc/Makefile").write_text(
        "srcdir = .\nC_OBJS = c.o duplicate.o\nCXX_OBJS = cp.o duplicate.o\n"
        "BACKEND = duplicate.o\nCODYLIB = cody.a\nLIBDEPS = ../lib.a\n"
        "include c/Make-lang.in\ninclude cp/Make-lang.in\n"
    )
    inputs = {}
    for index, name in enumerate(("c.o", "cp.o", "duplicate.o", "cody.a", "../lib.a", "checksum-options")):
        # Store references must survive in evidence, but not as raw output bytes.
        # Multiple 4096-byte blocks plus a non-aligned tail exercise dosum's
        # md5_process_block calls while the previous file still has pending bytes.
        payload = name.encode() + b"/nix/store/" + b"a" * 32 + b"-original\n" + bytes(range(256))
        data = b"ignored header!!" + (payload * 40)[:8192 + 29 + index]
        assert len(data) == 16 + 8192 + 29 + index
        path = Path("gcc") / name
        path.write_bytes(data)
        path.chmod(0o444)
        inputs[name] = (data, path.stat().st_mtime_ns)
    Path("lib.a").rename("lib-real.a")
    Path("lib.a").symlink_to("lib-real.a")

    def make(ok=True):
        result = subprocess.run(["make", "-C", "gcc", "-j2", "cc1-checksum.cc", "cc1plus-checksum.cc"])
        assert (result.returncode == 0) == ok

    def verify(stage):
        for target, first in (("cc1", "c.o"), ("cc1plus", "cp.o")):
            directory = Path(f"laut-gcc-checksums/{stage}/{target}-checksum.cc/1")
            argv = gzip.decompress((directory / "argv.nul.gz").read_bytes()).split(b"\0")
            assert argv.pop() == b""
            argv = [arg.decode() for arg in argv]
            expected = [first, "duplicate.o", "duplicate.o"]
            if target == "cc1plus": expected += ["cody.a"]
            expected += ["../lib.a", "checksum-options"]
            assert argv == expected, argv
            source = gzip.decompress((directory / "source.cc.gz").read_bytes())
            assert source == subprocess.check_output([generator, *argv], cwd="gcc")
            with tempfile.TemporaryDirectory() as replay, tarfile.open(directory / "inputs.tar.gz") as archive:
                members = archive.getmembers()
                assert [member.name for member in members] == argv
                replay_args = []
                for arg, member in zip(argv, members):
                    data = archive.extractfile(member).read()
                    assert data == inputs[arg][0]
                    assert (member.uid, member.gid, member.mtime, member.mode) == (0, 0, 1, 0o444)
                    # Keep every occurrence, including duplicate archive members.
                    path = Path(replay) / str(len(replay_args))
                    path.write_bytes(data)
                    replay_args.append(str(path))
                assert source == subprocess.check_output([generator, *replay_args])
                # A single concatenated payload hashes differently: dosum processes
                # full blocks before the pending tail from the preceding file.
                joined = Path(replay) / "joined"
                joined.write_bytes(b"ignored header!!" + b"".join(Path(p).read_bytes()[16:] for p in replay_args))
                assert source != subprocess.check_output([generator, str(joined)])
            assert source == Path(f"gcc/{target}-checksum.cc").read_bytes()
            for file in directory.iterdir():
                assert file.suffix == ".gz"
                assert file.read_bytes()[4:8] == b"\0" * 4

    def clean_sources():
        for target in ("cc1", "cc1plus"):
            Path(f"gcc/{target}-checksum.cc").unlink(missing_ok=True)

    make()
    verify("unbootstrapped")
    for name, (data, mtime) in inputs.items():
        assert (Path("gcc") / name).stat().st_mtime_ns == mtime
    baseline = {str(p.relative_to("laut-gcc-checksums")): p.read_bytes()
                for p in Path("laut-gcc-checksums").rglob("*.gz")}
    shutil.rmtree("laut-gcc-checksums")
    clean_sources()
    for name in inputs: os.utime(Path("gcc") / name, (100, 100))
    make()
    verify("unbootstrapped")
    assert baseline == {str(p.relative_to("laut-gcc-checksums")): p.read_bytes()
                        for p in Path("laut-gcc-checksums").rglob("*.gz")}
    # Repeated invocations in one stage retain both captures.
    clean_sources()
    make()
    assert len(list(Path("laut-gcc-checksums").glob("*/*/2"))) == 2
    for stage in ("stage1", "stage2"):
        Path("stage_current").write_text(stage + "\n")
        clean_sources()
        make()
        verify(stage)
    # Final bootstrap stage reuses the preceding source, without a generator call.
    Path("prev-gcc").mkdir()
    for target in ("cc1", "cc1plus"):
        shutil.copyfile(f"gcc/{target}-checksum.cc", f"prev-gcc/{target}-checksum.cc")
    Path("stage_current").write_text("stage3\n")
    Path("stage_final").write_text("stage3\n")
    clean_sources()
    make()
    assert not Path("laut-gcc-checksums/stage3").exists()
    # Failure must reach make and leave no successful-looking capture.
    Path("stage_final").unlink()
    Path("gcc/fail").touch()
    clean_sources()
    make(ok=False)
    assert not list(Path("laut-gcc-checksums/stage3").glob("*/*"))
    result = subprocess.run(["bash", "capture-checksum.sh", "failure.cc", "build/genchecksum", "c.o"], cwd="gcc")
    assert result.returncode == 23
    Path("gcc/fail").unlink()
    result = subprocess.run(["bash", "capture-checksum.sh", "missing.cc", "build/genchecksum", "missing.o"], cwd="gcc")
    assert result.returncode != 0
    assert not list(Path("laut-gcc-checksums/stage3").glob("*/*"))
    for target in ("cc1", "cc1plus"):
        shutil.copyfile(f"prev-gcc/{target}-checksum.cc", f"gcc/{target}-checksum.cc")
    for name, (data, _) in inputs.items():
        path = Path("gcc") / name
        assert path.read_bytes() == data
        assert path.stat().st_mode & 0o777 == 0o444
        assert path.stat().st_mtime == 100
    PY
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    install -m755 generator/genchecksum "$out/bin/genchecksum"
    # Test the actual phase, including mismatch and grep error handling.
    publish() { eval "$postInstallSaveChecksumPhase"; }
    cp gcc/cc1-checksum.cc original.cc
    printf 'not the installed checksum\n' > gcc/cc1-checksum.cc
    if ( publish ); then
      echo 'accepted a mismatching final source' >&2
      exit 1
    fi
    mv original.cc gcc/cc1-checksum.cc
    ( grep() { return 2; }; publish ) && exit 1
    mv "$checksum/captures" laut-gcc-checksums
    printf '%s' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$checksum/raw-reference"
    ( publish ) && exit 1
    rm "$checksum/raw-reference"
    mv "$checksum/captures" laut-gcc-checksums
  '';
  # The production pre-fixup phase now publishes the successful fixture run.
  postFixup = ''
    for frontend in cc1 cc1plus; do
      cmp "gcc/$frontend-checksum.cc" <(gzip -cd "$checksum/checksums/$frontend-checksum.cc.gz")
    done
    test -f "$checksum/captures/stage2/cc1-checksum.cc/1/inputs.tar.gz"
    touch "$out/passed"
  '';
})
