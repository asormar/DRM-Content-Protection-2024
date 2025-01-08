from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
import math
import base64
import json
import os

def int_to_bytes(i):
 return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
 return int.from_bytes(b, byteorder='big')

def decifrador(cosa_que_queremos_descifrar, key):
    iv = b'\x00' * 16  # Debe coincidir con el IV del servidor en este ejemplo simplificado

    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesDecryptor = aesCipher.decryptor()

    # Descifrar el contenido
    KEY_descifrada_licencia = aesDecryptor.update(cosa_que_queremos_descifrar) + aesDecryptor.finalize()
    #no hace falta padding porque tiene longitud 32
    return KEY_descifrada_licencia

def leer_json(nombre_archivo_json):
    try:
        with open(nombre_archivo_json, 'r') as archivo:
            return json.load(archivo)
    except FileNotFoundError:
        print(f"El archivo {nombre_archivo_json} no existe.")
        return None
    except json.JSONDecodeError:
        print(f"Error al leer el archivo JSON: {nombre_archivo_json}.")
        return None

clave_json = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'                    
with open('c_claves_aes.json', 'rb') as file:
    json_cifrado= file.read()
json_descifrado= decifrador(json_cifrado, clave_json)

with open('claves_aes.json', 'wb') as file:
    file.write(json_descifrado)
    

archivo_claves = leer_json("claves_aes.json")
#os.remove("claves_aes.json")
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
    #key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
    key_e = bytes.fromhex(clave_a_enviar)
    aesCipher = Cipher(algorithms.AES(key_licencias), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()
    KEY_cifrada = aesEncryptor.update(key_e)
    return KEY_cifrada
    
    
recibir_clave=True

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
                
                if recibir_clave==True:
                    clave_publica= mensaje
                    peer_public_key = serialization.load_pem_public_key(clave_publica)
                    #print(peer_public_key)
                    
                    numbers = peer_public_key.public_numbers()
                    n= numbers.n
                    e = numbers.e
                    #print(n,e)
                    clave_publica= (e,n)
                    
                    key_licencias= os.urandom(16)
                    #print(key_licencias)
                    
                    key_int = bytes_to_int(key_licencias)
                    
                    key_cifrada_para_UA= pow(key_int,e,n)
                    key_cifrada_para_UA= int_to_bytes(key_cifrada_para_UA)
                    socket.send(key_cifrada_para_UA)
                    
                    mensaje = socket.recv(2048)
                    #print(mensaje)
                    #print(mensaje)
                    recibir_clave=False
                
                print("Mensaje cifrado: ",mensaje,"\n")
                
                clave_publica= (7, 3233)
                mensaje_descifrado = descifrar_peticion_clave(mensaje, clave_publica)
                #print(mensaje_descifrado, "\n")

                # Enviar la clave cifrada al cliente al conectarse
                if mensaje_descifrado.startswith("<") and mensaje_descifrado.endswith(">"):
                    
                    archivo_id = mensaje_descifrado[1:-1]
                    info = archivo_claves[archivo_id]
                    KEY = info["clave"]
                    KEY_cifrada = cifrador_(KEY)
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
                
            
