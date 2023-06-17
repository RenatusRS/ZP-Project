import zlib


def compress(message: bytes) -> bytes:
    return zlib.compress(message)

def decompress(compressed: bytes) -> bytes:
    return zlib.decompress(compressed)