def generar_clave_aes():
    """
    Genera una clave AES aleatoria de 256 bits y un IV de 128 bits.
    :return: Diccionario con la clave y el IV.
    """
    clave = os.urandom(algorithms.AES.block_size // 8 * 2)  # 256 bits (32 bytes)
    return {"clave": clave.hex()}