import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from PIL import Image, ImageDraw, ImageFont, UnidentifiedImageError
import time
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def int_to_bytes(i):
 return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
 return int.from_bytes(b, byteorder='big')

def cifrador_sin_padding(cosa_que_queremos_cifrar,key): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    #key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurar que sea de 256 bits
    iv = b'\x00' * 16  # Para producción, usa un IV aleatorio
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    aesEncryptor = aesCipher.encryptor()

    # Cifrar el contenido
    mensaje_cifrado = aesEncryptor.update(cosa_que_queremos_cifrar)
    return mensaje_cifrado

def cifrador(cosa_que_queremos_cifrar,key): # Si es una imagen no hay que tocarlo, si es un mensaje hay que hacerle .encode() antes de entrar a la función
    # Preparar la clave y el cifrador AES en modo CBC (más seguro que ECB)
    #key = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]  # Asegurar que sea de 256 bits
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

def descifrar_peticion_clave(mensaje_cifrado, clave_publica):
    d, n = clave_publica
    # Decodificar la cadena base64 y convertirla nuevamente en una lista de enteros
    mensaje_cifrado = list(map(int, base64.b64decode(mensaje_cifrado).decode().split(",")))
    mensaje_descifrado = ''.join(chr(pow(char, d, n)) for char in mensaje_cifrado)
    return mensaje_descifrado

def generar_claves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    return private_key


def escribir():  # Crea una función para escribir
    while True:
        global message
        message = input() ###Preguntar por que al poner algo en el input se duplica el print
        message = "<" + str(s_contenidos.getsockname()) + ">: " + message
        if message[24:] == "quit":
            CDM.close()
            s_contenidos.close()
            s_licencias.close()
            break
        s_contenidos.send(message.encode())  # Enviar mensaje al servidor

# FIRMAS TIPICAS DE CONTENIDOS
firmas_archivos = [
    b'\x89PNG\r\n\x1a\n', #png
    b'\xff\xd8\xff\xe0', #jpeg y jpg
    b'\xff\xd8\xff\xe1', #jpeg y jpg
    b'ftypisom', #mp4
    b'ftypmp42', #mp4
    b'\x1a\x45\xdf\xa3', #mkv
    b'EBML' #mkv
]

lista_claves=[]

def escuchar():
    print(" Escribe el nombre del archivo o busca los disponibles (catalogo):")
    file_bytes = b""
    file_bytes_cdm = b""
    archivo_cifrado = "si"
    procesar_imagen = "apagado"
    enviar_clave=True
    global pedir_solicitud_cdm

    while True:        
        # Recibir mensaje del servidor
        data = s_contenidos.recv(1024)

        identificador_principio = data[:11]
        identificador_final = data[-5:]
        
        #DETECTAR SI ESTÁ CIFRADO
        for firma in firmas_archivos:
            if firma in data[:16]:
                archivo_cifrado = "no"
                break


        if identificador_principio == b"<CONTENIDO>":
            procesar_imagen = "encendido"
        
        elif identificador_principio != b"<CONTENIDO>" and procesar_imagen == "encendido":

            if identificador_final == b'<FIN>':
                file_bytes += data[:-5]
                file_bytes_cdm += data
                
                                    
                #ENVIAR CLAVE AES
                if enviar_clave==True:
                    
                    clave_privada= generar_claves()
                    #print(clave_privada)
                    clave_publica = clave_privada.public_key()
                    #print(clave_publica,"\n")
                    
                    public_key_bytes = clave_publica.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    
                    CDM.send(public_key_bytes)
                    s_licencias.send(public_key_bytes)
                    enviar_clave=False
                    
                    
                    private_numbers = clave_privada.private_numbers()
                    d = private_numbers.d
                    #print(n,e)
                                        
                    clave_publica = clave_privada.public_key()
                    public_numbers = clave_publica.public_numbers()
                    n= public_numbers.n
                    e = public_numbers.e
                    #print(n,e)
                    clave_publica= (n,e)
                    #print(clave_publica,"\n")
                    
                    clave_privada= (d,n)
                    #print(clave_publica,"\n")
                    
                    
                    key_cifrada_del_CDM= CDM.recv(1024)
                    key_int_CDM = bytes_to_int(key_cifrada_del_CDM)
                    key_CDM= pow(key_int_CDM,d,n)
                    key_CDM= int_to_bytes(key_CDM)
                    #print(key_CDM)
                    
                    key_cifrada_del_licencias= s_licencias.recv(1024)
                    key_int_licencias = bytes_to_int(key_cifrada_del_licencias)
                    key_licencias= pow(key_int_licencias,d,n)
                    key_licencias= int_to_bytes(key_licencias)
                    #print(key_licencias)
                    
                    #key_licencias= int_to_bytes(key_licencias)
                    CDM.send(cifrador_sin_padding(key_licencias, key_CDM))

                


                print(message[24:] + " recibid@ \n")
                print(f"El archivo {archivo_cifrado} está cifrado")

                if archivo_cifrado == "si":
                    
                    identificador_contenido = "<" + message[24:] + ">"
                    pedir_solicitud_cdm = "El archivo si esta cifrado " + identificador_contenido

                    pedir_solicitud_cdm = cifrador(pedir_solicitud_cdm.encode(),key_CDM)
                    print("\nMensaje cifrado ", pedir_solicitud_cdm, "\n")

                    CDM.send(pedir_solicitud_cdm)
                    firma = CDM.recv(1024)
                    print("Firma: ", firma, "\n")

                    s_licencias.send(firma)
                    clave_licencia = s_licencias.recv(1024)
                    CDM.send(clave_licencia)
                    if len(clave_licencia)==38: #no tiene clave registrada o falso positivo
                        print(clave_licencia.decode())
                    else:
                        print("Clave licencia cifrada: ", clave_licencia)
                        time.sleep(1) #Pequeño retraso para que no se solapen datos en el CDM

                        CDM.send(file_bytes_cdm)

                if archivo_cifrado == "no":
                    with open('carpeta_del_cliente/contenido_recibido_' + message[24:], 'wb') as file:
                        file.write(file_bytes)
                    identificador_contenido = "<" + message[24:] + ">"
                    no_cifrado = "El archivo no esta cifrado " + identificador_contenido
                    no_cifrado = cifrador(no_cifrado.encode(),key_CDM)
                    CDM.send(no_cifrado)

                print("-" * 40 + "\n Sigue escribiendo: \n")
                procesar_imagen = "apagado"

                file_bytes = b"" #Es necesario porque si no muestra la misma imagen al pedir otras (no se por que)
                file_bytes_cdm = b""
                archivo_cifrado = "si"

                False

            else:
                file_bytes += data
                file_bytes_cdm += data

        elif procesar_imagen == "apagado":
            key_s_contenidos = b'\xa9\x87\x1e\xdc\xc2\x3f\xb5\xb1\x9d\x4a\xee\x13\xc6\x92\x7a\xe5\x8b\x39\x14\xf2\xdf\x3e\x0d\x65\xb8\xc3\x7f\xa1\x45\x1d\x9c\x02'[:32]  # Asegurarse de que sea de 256 bits

            # Descifrar el contenido
            mensaje_descifrado = decifrador(data, key_s_contenidos)  

            # Eliminar el padding PKCS7
            unpadder = padding.PKCS7(128).unpadder()
            mensaje_despadding = unpadder.update(mensaje_descifrado) + unpadder.finalize()

            print("\nMensaje recibido: \n", mensaje_despadding.decode(), "\n")
            print("-" * 40 + "\n Sigue escribiendo:")

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
