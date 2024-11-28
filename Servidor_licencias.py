from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuración del servidor
direccion_IP_servidor = "127.0.0.1"
puerto_servidor = 7002

# Crear socket
servidor = socket(AF_INET, SOCK_STREAM)  # SOCK_STREAM indica que es TCP
servidor.bind((direccion_IP_servidor, puerto_servidor))
servidor.listen(5)  # Número máximo de conexiones en cola
servidor.setblocking(False)  # Hacer que el socket no bloquee

# Clave y configuración de cifrado
KEY_enviar = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'  # Asegúrate de que sea de 256 bits
key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
aesCipher = Cipher(algorithms.AES(key_DESZIFRAR_CLAVES), modes.CBC(iv))
aesEncryptor = aesCipher.encryptor()

# Cifrar la clave
KEY_cifrada = aesEncryptor.update(KEY_enviar)
#print("Clave cifrada:", KEY_cifrada)

# Listas para select
entradas = [servidor]  # Lista de sockets para lectura
salidas = []           # Lista de sockets listos para escritura
clientes = {}          # Para rastrear sockets conectados

#print("El servidor está escuchando...")

while True:
    # Usamos select para manejar múltiples sockets
    lista_lectura, lista_escritura, lista_excepciones = select.select(entradas, salidas, entradas)

    for socket_actual in lista_lectura:
        if socket_actual is servidor:
            # Nueva conexión entrante
            conexion, direccion = servidor.accept()
            print("Conexión establecida con:", direccion,"\n")
            # Enviar la clave cifrada al cliente al conectarse
            conexion.sendall(KEY_cifrada)
            print("Clave cifrada enviada \n")