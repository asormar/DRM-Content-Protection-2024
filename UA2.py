import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image, ImageDraw, ImageFont, UnidentifiedImageError
from pathlib import Path
import math
import base64

def cifrador(cosa_que_queremos_cifrar): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurar que sea de 256 bits
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()

    # Aplicar padding PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(cosa_que_queremos_cifrar) + padder.finalize()

    # Cifrar el contenido
    mensaje_cifrado = aesEncryptor.update(padded_data) + aesEncryptor.finalize()
    return mensaje_cifrado

def decifrador(cosa_que_queremos_descifrar, key):
    iv = b'\x00' * 16  # Debe coincidir con el IV del servidor en este ejemplo simplificado

    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesDecryptor = aesCipher.decryptor()

    # Descifrar el contenido
    KEY_descifrada_licencia = aesDecryptor.update(cosa_que_queremos_descifrar) + aesDecryptor.finalize()
    #no hace falta padding porque tiene longitud 32
    return KEY_descifrada_licencia


def escribir():  # Crea una función para escribir
    while True:
        global message
        message = input() ###Preguntar por que al poner algo en el input se duplica el print
        message = "<" + str(s_contenidos.getsockname()) + ">: " + message
        if message[24:] == "quit":
            s_contenidos.close()
            break
        s_contenidos.send(message.encode())  # Enviar mensaje al servidor
        
        #print(message[24:])

def escuchar():
    print("Escribe:")
    file_bytes = b""
    procesar_imagen = False

    while True:
        data = s_contenidos.recv(1024)

        identificador_principio = data[:11]
        identificador_final = data[-5:]

        if identificador_principio == b"<CONTENIDO>":
            procesar_imagen = True
            print("Inicio de contenido recibido.")

        elif identificador_final == b"<FIN>" and procesar_imagen:
            file_bytes += data[:-5]
            print("Archivo recibido completamente.")

            # Enviar archivo a CDM
            nombre_archivo = "<archivo>"+message[24:]+"<fin>"
            s_UA_CDM.send(cifrador(nombre_archivo.encode()))
            s_UA_CDM.send(file_bytes)

            print("Archivo enviado a CDM.")
            procesar_imagen = False
            file_bytes = b""  # Reiniciar buffer

        elif procesar_imagen:
            file_bytes += data

        else:
            key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]
            mensaje_descifrado = decifrador(data, key)
            print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")

            print("-" * 40 + "\nSigue escribiendo:")
            
            
      
# Crear el socket TCP
s_contenidos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_contenidos.connect(("127.0.0.1", 6001))
s_UA_CDM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_UA_CDM.connect(("127.0.0.1", 8003))
s_licencias = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_licencias.connect(("127.0.0.1", 7002))

hilo_escribir = threading.Thread(target=escribir)
hilo_escuchar = threading.Thread(target=escuchar)

hilo_escribir.start()
hilo_escuchar.start()

hilo_escribir.join()
hilo_escuchar.join()
