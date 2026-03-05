def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Implementa padding PKCS#7 según RFC 5652.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.
    """
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Padding invalido.")
    if any(b != pad_len for b in data[-pad_len:]):
        raise ValueError("Padding corrupto.")
    return data[:-pad_len]