import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as pkcs7
import json
import os

# Claves predefinidas
CLAVE_ENVIAR = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'
iv = b'\x00' * 16  # Para producción, usa un IV aleatorio

# Función para descifrar datos con AES (modo CBC)
def descifrar_datos_simetricos(clave, datos_cifrados):
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    datos_descifrados = decryptor.update(datos_cifrados) + decryptor.finalize()

    # Remover el relleno con PKCS7
    unpadder = pkcs7.PKCS7(128).unpadder()  # 128 bits = 16 bytes
    datos_descifrados = unpadder.update(datos_descifrados) + unpadder.finalize()

    return datos_descifrados

# Función para firmar el mensaje usando la clave privada del CDM
def firmar_mensaje(clave_privada, mensaje):
    firma = clave_privada.sign(
        mensaje.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return firma

# Función para procesar la solicitud de licencia y devolver la respuesta
def procesar_solicitud_licencia():
    # Generar claves RSA para el CDM (solo una vez)
    clave_privada_CDM = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    clave_publica_CDM = clave_privada_CDM.public_key()

    # Escuchar en el puerto 8081
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 8081))  # Escuchar en el puerto 8081
        s.listen(1)
        print("Esperando solicitud de la UA...")
        conn, addr = s.accept()
        with conn:
            mensaje_cifrado = conn.recv(1024)
            print(f"Solicitud recibida: {mensaje_cifrado}")

            # Descifrar el mensaje usando la clave simétrica
            mensaje_descifrado = descifrar_datos_simetricos(CLAVE_ENVIAR, mensaje_cifrado)

            # Procesar la solicitud (por ejemplo, verificar que el contenido esté cifrado)
            print(f"Mensaje descifrado: {mensaje_descifrado}")

            # Firmar el mensaje (respuesta) utilizando la clave privada del CDM
            respuesta = {"status": "OK", "message": "Licencia procesada correctamente", "content": "video.mp4"}
            mensaje_respuesta = json.dumps(respuesta)
            firma = firmar_mensaje(clave_privada_CDM, mensaje_respuesta)

            # Agregar la firma al mensaje de respuesta
            respuesta['firma'] = firma.hex()  # Convertimos la firma a un formato que se puede enviar (hexadecimal)

            # Cifrar la respuesta antes de enviarla de vuelta a la UA
            cipher = Cipher(algorithms.AES(CLAVE_ENVIAR), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # Asegurarse de que el mensaje sea múltiplo de 16 bytes antes de cifrar
            padder = pkcs7.PKCS7(128).padder()
            datos_relleno = padder.update(mensaje_respuesta.encode('utf-8')) + padder.finalize()

            datos_cifrados_respuesta = encryptor.update(datos_relleno) + encryptor.finalize()

            conn.sendall(datos_cifrados_respuesta)
            print(f"Licencia firmada y enviada de vuelta al usuario.")

# Ejecutar el servidor CDM
procesar_solicitud_licencia()
