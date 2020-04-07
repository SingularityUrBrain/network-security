import struct
from .core import encode_block, derive_keys


class DesKey():
    def __init__(self, key: bytes):
        self.__key = key

    def encrypt(self, message: bytes, padding=True):
        return handle_cipher(message, self.__key, padding, True)

    def decrypt(self, message: bytes, padding=True):
        return handle_cipher(message, self.__key, padding, False)

    def __hash__(self):
        return hash((self.__class__, self.__key))


def handle_cipher(message, key, padding, encryption):
    assert isinstance(key, bytes), "The key should be `bytes` or `bytearray`"
    assert len(key) == 8, "The key should be of length 8"
    message = guard_message(message, padding, encryption)

    dkeys = tuple(derive_keys(key))
    blocks = (struct.unpack(">Q", message[i: i + 8])[0]
              for i in range(0, len(message), 8))
    encoded_blocks = []
    for block in blocks:
        encoded_blocks.append(encode_block(block, dkeys, encryption))
    ret = b"".join(struct.pack(">Q", block) for block in encoded_blocks)
    return ret[:-ord(ret[-1:])] if not encryption and padding else ret


def guard_message(message, padding, encryption):
    assert isinstance(message, bytes), "The message should be bytes"
    length = len(message)
    # PKCS5 padding
    if encryption and padding:
        return message.ljust(length + 8 >> 3 << 3, bytes((8 - (length & 7), )))

    assert length & 7 == 0, (
        "The length of the message should be divisible by 8"
        "(or set `padding` to `True` in encryption mode)"
    )
    return message
