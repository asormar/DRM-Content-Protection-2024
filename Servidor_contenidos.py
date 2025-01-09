from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def cifrador(cosa_que_queremos_cifrar): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    key= b'\xa9\x87\x1e\xdc\xc2\x3f\xb5\xb1\x9d\x4a\xee\x13\xc6\x92\x7a\xe5\x8b\x39\x14\xf2\xdf\x3e\x0d\x65\xb8\xc3\x7f\xa1\x45\x1d\x9c\x02'[:32]
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()

    # Aplicar padding PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(cosa_que_queremos_cifrar) + padder.finalize()

    # Cifrar el contenido
    mensaje_cifrado = aesEncryptor.update(padded_data) + aesEncryptor.finalize()
    return mensaje_cifrado

# Almacenar dirección IP
dir_IP_servidor = "127.0.0.1"
puerto_servidor = 6001

# Introducir parámetros
dir_socket_servidor = (dir_IP_servidor, puerto_servidor)

# Constructor de la clase
s = socket(AF_INET, SOCK_STREAM)  # SOCK_STREAM indica que es TCP

# Vincular y escuchar
s.bind(dir_socket_servidor)
s.listen(5)  # Los que puede dejar en cola antes de empezar

inputs = [s]
catalogo= False
contenido_en_lista = os.listdir("carpeta_contenidos")

while True:
    ready_to_read, ready_to_write, in_error = select.select(inputs, [], [])
    
    for socket in ready_to_read:
        if socket is s:
            cliente, cliente_data = s.accept()
            print(str(cliente.getpeername()), "se unió al grupo \n")
            inputs.append(cliente)
        else:
            
            mensaje = socket.recv(2048).decode()
            print(mensaje, "\n")
            if "catalogo" == mensaje[24:]:
                
                # Leer el contenido del archivo y enviarlo al cliente
                try:
                    contenido_en_lista = os.listdir("carpeta_contenidos")
                    contenido=""
                    
                    for imagenes in contenido_en_lista:
                        contenido += imagenes+"\n"
                    print(contenido)
                    
                    mensaje_cifrado= cifrador(contenido.encode())
                    
                    
                    # Enviar el mensaje cifrado
                    socket.send(mensaje_cifrado)
                    print("Mensaje enviado")
                    print("-"*40+"\n")
                        
                except FileNotFoundError:
                    socket.send(cifrador("No hay contenidos".encode()))

            
            else:
                try:
                    contenido_en_lista = os.listdir("carpeta_contenidos")
                    archivo=""
                    recurso=""
                    for i in contenido_en_lista:
                        if i==mensaje[24:]:
                            recurso= i
                            #print(recurso)
                            #print(archivo)
                            
                    
                    with open("carpeta_contenidos/"+recurso, "rb") as archivo:
                        imagen = archivo.read()
                        #print(contenido_en_lista)

                        
                        socket.send("<CONTENIDO>".encode())
                        socket.sendall(imagen)
                        socket.send("<FIN>".encode())
                        print(recurso,"enviad@ \n", "-"*40)
                        
                        
                except (FileNotFoundError, PermissionError): # Si solo pones img1 da error de permiso
                    socket.send(cifrador("Error: mensaje no reconocido".encode()))
                    print("-"*40)
