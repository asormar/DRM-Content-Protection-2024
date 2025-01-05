from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import math
import base64
import json
import os

def leer_json(nombre_archivo_json):
    """
    Lee el archivo JSON y devuelve su contenido como un diccionario.
    :param nombre_archivo_json: Ruta del archivo JSON.
    :return: Diccionario con las claves y los IV.
    """
    try:
        with open(nombre_archivo_json, 'r') as archivo:
            return json.load(archivo)
    except FileNotFoundError:
        print(f"El archivo {nombre_archivo_json} no existe.")
        return None
    except json.JSONDecodeError:
        print(f"Error al leer el archivo JSON: {nombre_archivo_json}.")
        return None

archivo_claves = leer_json("claves_aes.json")
#print(archivo_claves)

def descifrar_peticion_clave(mensaje_cifrado, clave_publica):
    d, n = clave_publica
    # Decodificar la cadena base64 y convertirla nuevamente en una lista de enteros
    mensaje_cifrado = list(map(int, base64.b64decode(mensaje_cifrado).decode().split(",")))
    mensaje_descifrado = ''.join(chr(pow(char, d, n)) for char in mensaje_cifrado)
    return mensaje_descifrado

# Almacenar dirección IP
dir_IP_servidor = "127.0.0.1"
puerto_servidor = 7002

# Introducir parámetros
dir_socket_servidor = (dir_IP_servidor, puerto_servidor)

# Constructor de la clase
s = socket(AF_INET, SOCK_STREAM)  # SOCK_STREAM indica que es TCP

# Vincular y escuchar
s.bind(dir_socket_servidor)
s.listen(5)  # Los que puede dejar en cola antes de empezar
inputs = [s]

def cifrador_(clave_a_enviar):
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
    key_e = bytes.fromhex(clave_a_enviar)
    aesCipher = Cipher(algorithms.AES(key_DESZIFRAR_CLAVES), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()
    KEY_cifrada = aesEncryptor.update(key_e)
    return KEY_cifrada
    
    
# Clave y configuración de cifrado
"""
KEY_enviar = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'  # Asegúrate de que sea de 256 bits
key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
aesCipher = Cipher(algorithms.AES(key_DESZIFRAR_CLAVES), modes.CBC(iv))
aesEncryptor = aesCipher.encryptor()

# Cifrar la clave
KEY_cifrada = aesEncryptor.update(KEY_enviar)"""
#print("Clave cifrada:", KEY_cifrada)

#print("El servidor está escuchando...")

while True:
    ready_to_read, ready_to_write, in_error = select.select(inputs, [], [])
    
    for socket in ready_to_read:
        if socket is s:
            cliente, cliente_data = s.accept()
            print(str(cliente.getpeername()), "se unió al grupo \n")
            inputs.append(cliente)
        else:
            try:
                mensaje = socket.recv(1024)
                print("Mensaje cifrado: ",mensaje)
                
                clave_publica= (7, 3233)
                mensaje_descifrado = descifrar_peticion_clave(mensaje, clave_publica)
                print(mensaje_descifrado, "\n")

                # Enviar la clave cifrada al cliente al conectarse
                if mensaje_descifrado.startswith("<") and mensaje_descifrado.endswith(">"):
                    archivo_id = mensaje_descifrado[1:-1]
                    info = archivo_claves[archivo_id]
                    KEY_cifrada = info["clave"]
                    KEY_cifrada = cifrador_(KEY_cifrada)
                    socket.sendall(KEY_cifrada)
                    print("Clave cifrada enviada:",KEY_cifrada)
                    print("-"*40, "\n")
                    
                else:
                    print("Firma no valida")
                    socket.send("Firma no valida".encode())
                    
            except ValueError: # al escuchar todo el rato no para de descifrar y da error
                print("Firma no procesable"+"\n"+"-"*40)
                socket.send("Firma no procesable".encode()) # Da error al recibir el mensaje porque no está firmado con RSA
                pass
            except KeyError:
                print("Este archivo no tiene clave registrada"+"\n"+"-"*40)
                socket.send("Este archivo no tiene clave registrada".encode())
                
            
