import struct


def left_rotate(value, shift):
    # Bitwise left rotate a 32-bit integer.
    return ((value << shift) | (value >> (32 - shift))) & 0xffffffff


def sha1(message):
    # Initial hash values
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Message length in bits
    ml = len(message) * 8

    # Pre-processing of message
    message += b'\x80'
    message += b'\x00' * ((56 - len(message) % 64) % 64)
    message += struct.pack('>Q', ml)

    # Process the message in successive 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # Break chunk into sixteen 32-bit big-endian words
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop of SHA-1 algorithm
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e, d, c, b, a = d, c, left_rotate(b, 30), a, temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value
    return (h0.to_bytes(4, 'big') +
            h1.to_bytes(4, 'big') +
            h2.to_bytes(4, 'big') +
            h3.to_bytes(4, 'big') +
            h4.to_bytes(4, 'big'))


def hmac_sha1(key, message):
    block_size = 64
    # Shorten or zero-pad the key to block size
    if len(key) > block_size:
        key = sha1(key)
    if len(key) < block_size:
        key = key + b'\0' * (block_size - len(key))

    # XOR key with outer and inner pad constants
    o_key_pad = bytearray([b ^ 0x5C for b in key])
    i_key_pad = bytearray([b ^ 0x36 for b in key])

    # Compute HMAC: SHA1(o_key_pad || SHA1(i_key_pad || message))
    inner_hash = sha1(i_key_pad + message)
    return sha1(bytes(o_key_pad) + inner_hash)



