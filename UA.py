import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pkcs7
import json
import os

# Claves predefinidas
CLAVE_ENVIAR = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'
iv = b'\x00' * 16  # Para producción, usa un IV aleatorio

# Función para verificar si un archivo está cifrado
def esta_cifrado(ruta_archivo):
    try:
        with open(ruta_archivo, 'rb') as f:
            datos = f.read()  # Leer todo el archivo
            print("Datos leídos del archivo:", datos[:64])  # Imprimir los primeros 64 bytes para depurar

            aesCipher = Cipher(algorithms.AES(CLAVE_ENVIAR), modes.CBC(iv))
            aesDecryptor = aesCipher.decryptor()

            try:
                datos_descifrados = aesDecryptor.update(datos) + aesDecryptor.finalize()
                print("Descifrado:", datos_descifrados)
                return False  # Si es descifrado correctamente, no está cifrado
            except Exception as e:
                print("Error al descifrar:", e)
                return True  # Si no se puede descifrar, el archivo está cifrado
    except Exception as e:
        print("Error al leer el archivo:", e)
        return False

# Función para cifrar datos con AES (modo CBC)
def cifrar_datos_simetricos(clave, datos):
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Asegurarse de que el mensaje sea múltiplo de 16 bytes antes de cifrar
    padder = pkcs7.PKCS7(128).padder()  # 128 bits = 16 bytes
    datos_relleno = padder.update(datos.encode('utf-8')) + padder.finalize()
    
    datos_cifrados = encryptor.update(datos_relleno) + encryptor.finalize()
    return datos_cifrados

# Función para enviar la solicitud de licencia al CDM
def solicitar_licencia(contenido):
    # Cifrar la solicitud de licencia
    mensaje = {"request": "license", "content": contenido}
    mensaje_json = json.dumps(mensaje)
    mensaje_cifrado = cifrar_datos_simetricos(CLAVE_ENVIAR, mensaje_json)

    # Enviar la solicitud al CDM
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 8081))  # Conectarse al CDM en el puerto 8081
        s.sendall(mensaje_cifrado)

        # Recibir la respuesta del CDM
        respuesta_cifrada = s.recv(1024)
        print(f"Respuesta cifrada recibida: {respuesta_cifrada}")

        # Descifrar la respuesta
        cipher = Cipher(algorithms.AES(CLAVE_ENVIAR), modes.CBC(iv))
        decryptor = cipher.decryptor()
        respuesta_descifrada = decryptor.update(respuesta_cifrada) + decryptor.finalize()
        
        # Remover el relleno de la respuesta
        unpadder = pkcs7.PKCS7(128).unpadder()
        respuesta_descifrada = unpadder.update(respuesta_descifrada) + unpadder.finalize()

        print(f"Respuesta descifrada: {respuesta_descifrada.decode('utf-8')}")

# Verificar si el archivo está cifrado y solicitar la licencia
def principal():
    ruta_archivo = r'C:\Users\Bryan\Desktop\GTDM\Segder\pruebas\contenidos\img1.png'
    # Cambiar según el archivo a verificar
    if esta_cifrado(ruta_archivo):
        print(f"El archivo {ruta_archivo} está cifrado. Solicitando licencia...")
        solicitar_licencia(ruta_archivo)
    else:
        print(f"El archivo {ruta_archivo} no está cifrado.")

if __name__ == '__main__':
    principal()
