from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

def decifrador(data, key):
    iv = b'\x00' * 16
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = aesCipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def descifrar_peticion_clave(mensaje_cifrado, clave_publica):
    d, n = clave_publica
    mensaje_cifrado = list(map(int, base64.b64decode(mensaje_cifrado).decode().split(",")))
    mensaje_descifrado = ''.join(chr(pow(char, d, n)) for char in mensaje_cifrado)
    return mensaje_descifrado

# Almacenar dirección IP
dir_IP_servidor = "127.0.0.1"
puerto_servidor = 7002

# Configuración del servidor
dir_socket_servidor = (dir_IP_servidor, puerto_servidor)
s = socket(AF_INET, SOCK_STREAM)
s.bind(dir_socket_servidor)
s.listen(5)
inputs = [s]

# Clave y configuración de cifrado
KEY_enviar = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'  # Clave de 32 bytes
key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
iv = b'\x00' * 16
aesCipher = Cipher(algorithms.AES(key_DESZIFRAR_CLAVES), modes.CBC(iv))
aesEncryptor = aesCipher.encryptor()
# --- Cifrar la clave con padding ---
KEY_cifrada = aesEncryptor.update(key_DESZIFRAR_CLAVES) 
print("Clave cifrada (con padding):", KEY_cifrada)

# Servidor escuchando
print("El servidor está escuchando...")

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
                
                clave_publica = (7, 3233)
                msg = decifrador(mensaje, KEY_enviar)
                mensaje_descifrado = descifrar_peticion_clave(msg, clave_publica)
                print(mensaje_descifrado, "\n")

                if mensaje_descifrado == "dame la clave":
                    socket.send(KEY_cifrada)  # Enviar la clave cifrada con padding
                    print("Clave cifrada enviada \n")
                    print("-" * 40, "\n")
                else:
                    socket.send(b"Firma no valida")
                    
            except ValueError:
                socket.send(b"Firma no valida")  # Si ocurre un error al descifrar
                pass
