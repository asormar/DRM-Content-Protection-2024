from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def decifrador(cosa_que_queremos_descifrar, key):
    iv = b'\x00' * 16  # Debe coincidir con el IV del servidor en este ejemplo simplificado

    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesDecryptor = aesCipher.decryptor()

    # Descifrar el contenido
    KEY_descifrada_licencia = aesDecryptor.update(cosa_que_queremos_descifrar) + aesDecryptor.finalize()
    #no hace falta padding porque tiene longitud 32
    return KEY_descifrada_licencia

# Almacenar dirección IP
dir_IP_servidor= "127.0.0.1"
puerto_servidor = 8003

# Introducir parámetros
dir_socket_servidor =(dir_IP_servidor, puerto_servidor)

# Constructor de la clase
s = socket(AF_INET, SOCK_STREAM) #SOCK_STREAM indica que es TCP

#s.setblocking(False)

s.bind(dir_socket_servidor)

s.listen(5) # Los que puede dejar en cola antes de empezar

inputs= [s]

while True:
    ready_to_read, ready_to_write, in_error = select.select(inputs, [], [])
    
    for socket in ready_to_read:
        if socket is s:
            cliente, cliente_data = s.accept()
            #cliente.setblocking(False)
            inputs.append(cliente)
            print()
        
        else:
            try:
                mensaje = socket.recv(2048)
                if mensaje==b"":
                    continue
                print(mensaje)
                
                
                for t in inputs:
                    if (t != s) and (t != socket):
                        t.send(mensaje)
            except ConnectionAbortedError: # al escuchar todo el rato no para de descifrar y da error
                pass
            
