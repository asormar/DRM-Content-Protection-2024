
from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import json


def generar_clave_aes():
    """
    Genera una clave AES aleatoria de 256 bits y un IV de 128 bits.
    :return: Diccionario con la clave y el IV.
    """
    clave = os.urandom(algorithms.AES.block_size // 8 * 2)  # 256 bits (32 bytes)
    return {"clave": clave.hex()}
clave = generar_clave_aes()

def cifrador(cosa_que_queremos_cifrar,clave): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    
    
    key = bytes.fromhex(clave["clave"])
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()

    # Aplicar padding PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(cosa_que_queremos_cifrar) + padder.finalize()

    # Cifrar el contenido
    mensaje_cifrado = aesEncryptor.update(padded_data) + aesEncryptor.finalize()
        
    return mensaje_cifrado

m = input("Nombre del archivo: ")

with open("carpeta_contenidos/" + m, "rb") as file:
    archivo_a_cifrar = file.read()
    with open("carpeta_contenidos/c_"+ m, "wb") as archivo:
        archivo.write(cifrador(archivo_a_cifrar,clave))
with open("claves_aes.json", "r") as a_json:
    datos = json.load(a_json)
datos["c_"+m] = clave
with open("claves_aes.json", 'w') as archivo_json:
    json.dump(datos, archivo_json, indent=4)

