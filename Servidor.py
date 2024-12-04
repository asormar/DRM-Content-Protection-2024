from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

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
                print("Mensaje recibido de", socket.getpeername(), ":", mensaje,"\n")
                
                # Leer el contenido del archivo y enviarlo al cliente
                try:

                    contenido=""
                    
                    for imagenes in contenido_en_lista:
                        contenido += imagenes+"\n"
                    print(contenido)
                    
                    mensaje_cifrado= cifrador(contenido.encode())
                    
                    
                    # Enviar el mensaje cifrado
                    socket.send(mensaje_cifrado)
                    print("Mensaje enviado \n\n")
                        
                except FileNotFoundError:
                    socket.send(cifrador("No hay contenidos".encode()))

            
            else:
                try:
                    archivo=""
                    recurso=""
                    for i in contenido_en_lista:
                        if i==mensaje[24:]:
                            recurso= i
                            #print(archivo)
                            
                    
                    with open("carpeta_contenidos/"+recurso, "rb") as archivo:
                        imagen = archivo.read()
                        print(contenido_en_lista)

                        
                        socket.send("<CONTENIDO>".encode())
                        socket.sendall(imagen)
                        socket.send("<FIN>".encode())
                        print(recurso,"enviad@ \n", "-"*40)
                        
                        
                except (FileNotFoundError, PermissionError): # Si solo pones img1 da error de permiso
                    socket.send(cifrador("Error: mensaje no reconocido".encode()))
