from dataclasses import dataclass


@dataclass(frozen=True)
class TrustedKey:
    key_bytes: bytes
    name: str

    def __hash__(self):
        return hash((self.key_bytes, self.name))

    def __eq__(self, other):
        if not isinstance(other, TrustedKey):
            return False
        return self.key_bytes == other.key_bytes and self.name == other.name


def parse_nix_public_key(key_path: str) -> TrustedKey:
    # Imported lazily so sign-only builds (which omit verify-side symbols)
    # can still import this module without the verify subcommand running.
    from lautr import parse_nix_public_key as _rust_parse

    name, key_bytes = _rust_parse(key_path)
    return TrustedKey(name=name, key_bytes=bytes(key_bytes))
