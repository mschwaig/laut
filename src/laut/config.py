from pathlib import Path


class Config:
    def __init__(self):
        self.debug = False
        self.allow_ia = False
        self.preimage_index = None
        self.cache_urls = []
        self.trusted_keys = []

config = Config()
