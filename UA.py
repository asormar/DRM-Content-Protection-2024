import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image, ImageDraw, ImageFont, UnidentifiedImageError
from pathlib import Path
import math
import base64
import time

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
    file_bytes= b""
    file_bytes_cdm=b""
    archivo_cifrado=""
    procesar_imagen= "apagado"
    global pedir_solicitud_cdm
    
    while True:        
        # Recibir mensaje del servidor
        data = s_contenidos.recv(1024)
        
        
        identificador_principio= data[:11]
        identificador_final= data[-5:]
        
        
        if identificador_principio == b"<CONTENIDO>":
            procesar_imagen= "encendido"
            
            
        elif identificador_principio != b"<CONTENIDO>" and procesar_imagen == "encendido":
            

            if identificador_final == b'<FIN>':
                
                file_bytes += data[:-5]
                file_bytes_cdm += data

                if len(file_bytes)%16==0:
                    archivo_cifrado="si"
                else:
                    archivo_cifrado="no"
                    
                                            

                print(message[24:]+ " recibid@ \n")
                print(f"El archivo {archivo_cifrado} está cifrado")
                
                if archivo_cifrado=="si":
                    identificador_contenido= "<"+message[24:]+">"
                    pedir_solicitud_cdm="El archivo si esta cifrado "+identificador_contenido
                    
                    pedir_solicitud_cdm= cifrador(pedir_solicitud_cdm.encode())
                    print("Mensaje cifrado ",pedir_solicitud_cdm, "\n")
                    
                    CDM.send(pedir_solicitud_cdm)
                    firma= CDM.recv(1024)
                    print("Firma: ",firma,"\n")
                    
                    
                    s_licencias.send(firma)
                    clave_licencia= s_licencias.recv(1024)
                    print("Clave licencia: ",clave_licencia)
                    CDM.send(clave_licencia)
                    time.sleep(1) #Pequeño retraso para que no se solapen datos en el CDM
                    
                    CDM.send(file_bytes_cdm)
                    
                if archivo_cifrado=="no":
                    with open('carpeta_del_cliente/contenido_recibido_'+message[24:], 'wb') as file:
                        file.write(file_bytes)
                    identificador_contenido= "<"+message[24:]+">"
                    no_cifrado = "El archivo no esta cifrado " + identificador_contenido
                    no_cifrado = cifrador(no_cifrado.encode())
                    CDM.send(no_cifrado)
  
                print("-"*40+"\n Sigue escribiendo: \n")
                procesar_imagen= "apagado"
              
                file_bytes= b"" #Es necesario porque si no muestra la misma imagen al pedir otras (no se por que)
                file_bytes_cdm= b""
                
                False
            
            else:
                file_bytes += data
                file_bytes_cdm += data
                

            
            
            
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
s_contenidos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_contenidos.connect(("127.0.0.1", 6001))
CDM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CDM.connect(("127.0.0.1", 8003))
s_licencias = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_licencias.connect(("127.0.0.1", 7002))

hilo_escribir = threading.Thread(target=escribir)
hilo_escuchar = threading.Thread(target=escuchar)

hilo_escribir.start()
hilo_escuchar.start()

hilo_escribir.join()
hilo_escuchar.join()
