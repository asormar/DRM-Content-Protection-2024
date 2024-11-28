import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image

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
        message = "<" + str(sock.getsockname()) + ">: " + message
        if message[24:] == "quit":
            sock.close()
            break
        sock.send(message.encode())  # Enviar mensaje al servidor
        #print(message[24:])
        
def escuchar():
    print("Escribe:")
    file_bytes= b""
    
    procesar_imagen= "apagado"
    
    i=0
    
    while True:        
        # Recibir mensaje del servidor
        data = sock.recv(1024)
        
        identificador_principio= data[:8]
        identificador_final= data[-5:]
        
        
        if identificador_principio == b"<IMAGEN>":
            procesar_imagen= "encendido"
            
            
        elif identificador_principio != b"<IMAGEN>" and procesar_imagen == "encendido":
            
            with open('carpeta_del_cliente/imagen_recibida_'+message[24:]+'.png', 'wb') as file:
                

                if identificador_final == b'<FIN>':
                    
                    file_bytes += data[:-5]
                    
                    
                    # Server configurations
                    SERVER1 = ('127.0.0.1', 7002)
                    i += 1

                    # Conectar Server licencias
                    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client1.connect(SERVER1)
                    #print(f"Connected to Server 1: {SERVER1}")
                    KEY_cifrada_licencia = client1.recv(1024)
                    client1.close()
                    
                    #print(key)
                    
                    
                    #DESZIFRADOR LLAVE
                    
                    key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'

                    # Descifrar el contenido
                    KEY_descifrada_licencia = decifrador(KEY_cifrada_licencia, key_DESZIFRAR_CLAVES)  

                    #print(KEY_descifrada_licencia)
                    
                    
                    
                    
                    
                    #DESZIFRADOR IMAGENES
                    #key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurarse de que sea de 256 bits

                    imagen_descifrada = decifrador(file_bytes, KEY_descifrada_licencia)  

                    # Eliminar el padding PKCS7
                    unpadder = padding.PKCS7(128).unpadder()
                    img_despadding = unpadder.update(imagen_descifrada) + unpadder.finalize()

                    #print("Mensaje recibido: \n", mensaje_despadding.decode(),"\n")
                    
                    
                    
                    
                    file.write(img_despadding)
                    
                    print(message[24:]+" procesando paquete... ",len(data),"\n")
                    
                    print("Imagen recibida \n")
                    print("-"*40+"\n Sigue escribiendo:")
                    procesar_imagen= "apagado"
                    
                    imagen_recibida = Image.open('carpeta_del_cliente/'+'imagen_recibida_'+message[24:]+'.png')
                    imagen_recibida.show()
                    
                    file_bytes= b"" #Es necesario porque si no muestra la misma imagen al pedir otras (no se por que)

                    False
                
                else:
                    file_bytes += data
                    
                    print(message[24:]+" procesando paquete... ",len(data))

                
            
            
        elif procesar_imagen=="apagado":
            key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurarse de que sea de 256 bits

            # Descifrar el contenido
            mensaje_descifrado = decifrador(data, key)  

            # Eliminar el padding PKCS7
            unpadder = padding.PKCS7(128).unpadder()
            mensaje_despadding = unpadder.update(mensaje_descifrado) + unpadder.finalize()

            print("\n Mensaje recibido: \n", mensaje_despadding.decode(),"\n")
            print("-"*40+"\n Sigue escribiendo:")
        
    
        
# Crear el socket TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 6001))

hilo_escribir = threading.Thread(target=escribir)
hilo_escuchar = threading.Thread(target=escuchar)

hilo_escribir.start()
hilo_escuchar.start()

hilo_escribir.join()
hilo_escuchar.join()
