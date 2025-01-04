
from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def cifrador(cosa_que_queremos_cifrar): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    clave = "29006cbdbb4af315c2cbd6dacd40d2555553b747366432b7135676609923f3bc"
    key = bytes.fromhex(clave)
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()

    # Aplicar padding PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(cosa_que_queremos_cifrar) + padder.finalize()

    # Cifrar el contenido
    mensaje_cifrado = aesEncryptor.update(padded_data) + aesEncryptor.finalize()
        
    return mensaje_cifrado
with open("carpeta_cifrador/jagger.png", "rb") as file:
    archivo_a_cifrar = file.read()
    with open("carpeta_contenidos/jagger.png", "wb") as archivo:
        archivo.write(cifrador(archivo_a_cifrar))
