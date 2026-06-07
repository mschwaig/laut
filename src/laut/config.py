
class Config:
    def __init__(self):
        self.debug = False
        # When true, sign_impl emits the `payload.in.debug` block (drv_name,
        # rdrv_path, rdrv_aterm_ca_preimage). Independent of `debug` (which
        # only controls log verbosity) — preimages should never be published
        # unless the signer opted in.
        self.include_preimage = False
        self.allow_ia = False

config = Config()
