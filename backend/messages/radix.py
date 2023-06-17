import base64


def message_to_radix64(message: bytes) -> bytes:
    return base64.b64encode(message)

def radix64_to_message(radix64: bytes) -> bytes:
    return base64.b64decode(radix64)

def isBase64(s) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
