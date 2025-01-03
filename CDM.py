from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import math

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

def firmar_peticion_clave(mensaje, clave_privada):
    e, n = clave_privada
    mensaje_cifrado = [pow(ord(char), e, n) for char in mensaje]
    # Convertir la lista de enteros a una cadena codificada en base64
    mensaje_cifrado_codificado = base64.b64encode(",".join(map(str, mensaje_cifrado)).encode()).decode()
    return mensaje_cifrado_codificado

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

procesar_imagen= "apagado"
file_bytes=b""

while True:
    ready_to_read, ready_to_write, in_error = select.select(inputs, [], [])
    
    for socket in ready_to_read:
        if socket is s:
            cliente, cliente_data = s.accept()
            #cliente.setblocking(False)
            inputs.append(cliente)
            print(str(cliente.getpeername()), "se unió al grupo \n")

        
        else:
            try:
                mensaje = socket.recv(2048)
                
                if mensaje==b"":
                    continue
                
                if procesar_imagen== "apagado":
                    key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurarse de que sea de 256 bits
                    mensaje_descifrado = decifrador(mensaje, key)  

                    # Eliminar el padding PKCS7
                    unpadder = padding.PKCS7(128).unpadder()
                    mensaje_despadding = unpadder.update(mensaje_descifrado) + unpadder.finalize()
                    print(mensaje_despadding.decode(), "\n")
                    
                    if mensaje_despadding.decode()[24]=="<" and mensaje_despadding.decode()[-1]==">":
                        identificador_contenido= mensaje_despadding.decode()[25:-1]
                    
                    
                    clave_privada = (1783, 3233)
                    socket.send(firmar_peticion_clave("dame la clave",clave_privada).encode())
                    
                elif procesar_imagen=="encendido":
                    
                    file_bytes +=mensaje
                    
                    if file_bytes[-5:]==b'<FIN>':
                        file_bytes = file_bytes[:-5]
                        #print(len(file_bytes))
                         
                        imagen_descifrada = decifrador(file_bytes, clave_licencia_descifrada)  
                        unpadder = padding.PKCS7(128).unpadder()
                        img_despadding = unpadder.update(imagen_descifrada) + unpadder.finalize()
                        file_bytes= b""
                        
                        with open('carpeta_del_cliente/contenido_recibido_'+identificador_contenido, 'wb') as file:
                            file.write(img_despadding)
                            print("Contenido descifrado guardado \n"+"-"*40)
                            procesar_imagen= "apagado"
                            
                             
                            
            except ConnectionAbortedError: # al escuchar todo el rato no para de descifrar y da error
                pass
            except ValueError: # Da este error al intentar descifar la clave porque esta no tiene padding
                key_DESZIFRAR_CLAVES = b'\x0c4*A)\xb6\xc8\xf1\x12\xdf\xb3q\x1b\xb7)\xcc\xceBrPL\xf9&\x90)m\x80s$\x01\x0e\x8e'
                clave_licencia_descifrada = decifrador(mensaje, key_DESZIFRAR_CLAVES)
                print("Clave de licencia descifrada: ", clave_licencia_descifrada, "\n")
                #clave_licencia_descifrada = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'  # Asegúrate de que sea de 256 bits
                #print(clave_licencia_descifrada==b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN')
                procesar_imagen= "encendido"
                
            

