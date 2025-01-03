import socket
import threading
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import math
import base64
from PIL import Image, ImageDraw, ImageFont, UnidentifiedImageError
from pathlib import Path
import os
# --- Funciones de cifrado y descifrado ---
clave_privada = (1783, 3233)

def marcar(imagen):
    # Abrir la imagen base y asegurarse de que esté en modo RGBA
    imagen = Image.open(imagen).convert("RGBA")

    # Crear una nueva imagen de marca de agua en RGBA
    marca_agua = Image.new("RGBA", imagen.size, (0, 0, 0, 0))
    dibujar = ImageDraw.Draw(marca_agua)

    # Definir las propiedades de la fuente y el texto
    tamaño_fuente = 50  # Ajustar el tamaño según sea necesario
    ruta_fuente = "arial.ttf"  # Reemplazar con la ruta a una fuente .ttf en tu sistema
    fuente = ImageFont.truetype(ruta_fuente, tamaño_fuente)
    texto_marca_agua = "MARCA DE AGUA"

    # Calcular la posición del texto
    caja_texto = dibujar.textbbox((0, 0), texto_marca_agua, font=fuente)
    x = 450  # + derecha      - izquierda
    y = 450  # + abajo        - arriba

    # Dibujar el texto en la marca de agua
    color_relleno = (0, 0, 0, 128)  # Negro semitransparente
    dibujar.text((x, y), texto_marca_agua, font=fuente, fill=color_relleno)

    # Crear una imagen de marca de agua rotada
    marca_agua_rotada = Image.new("RGBA", imagen.size, (0, 0, 0, 0))
    dibujar_rotada = ImageDraw.Draw(marca_agua_rotada)
    dibujar_rotada.text((x, y), texto_marca_agua, font=fuente, fill=color_relleno)

    # Rotar la marca de agua
    marca_agua_rotada = marca_agua_rotada.rotate(45, center=(x, y))

    # Combinar las imágenes usando alpha_composite
    resultado = Image.alpha_composite(imagen, marca_agua_rotada)

    # Guardar la imagen final
    resultado.save('carpeta_del_cliente/contenido_recibido_'+message[24:])


def es_clave_aes_valida(clave):
    # Verificar longitud de la clave
    if len(clave) not in [16, 24, 32]:
        return False
    else:
        return True

def firmar_peticion_clave(mensaje, clave_privada):
    e, n = clave_privada
    mensaje_cifrado = [pow(ord(char), e, n) for char in mensaje]
    mensaje_cifrado_codificado = base64.b64encode(
        ",".join(map(str, mensaje_cifrado)).encode()
    ).decode()
    return mensaje_cifrado_codificado

def cifrador(data, key):
    iv = b'\x00' * 16
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = aesCipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decifrador(data, key):
    iv = b'\x00' * 16
    aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = aesCipher.decryptor()
    
    try:
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    except:
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        return decrypted_data

# --- Configuración del servidor ---

dir_IP_servidor = "127.0.0.1"
puerto_servidor = 8003
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((dir_IP_servidor, puerto_servidor))
server_socket.listen(5)
print(f"Servidor iniciado en {dir_IP_servidor}:{puerto_servidor}")

inputs = [server_socket]
key_simetrica = b'\xec\x13x\xa2z\xc7\x8e@>\x1b\xaa\r\x84\x03\x1c\x05V\x95\x80\xda\nN\xed\x1fbk\xf1z\n\x05tN'[:32]

# --- Manejo de clientes ---
def manejar_cliente(cliente_socket):
    while True:
        try:
            data = cliente_socket.recv(1024)
            if not data:
                break
            data_descifrada = decifrador(data,key_simetrica)
            print(f"Datos recibidos: {data_descifrada}")
            
            if data_descifrada.startswith(b'<archivo>') and data_descifrada.endswith(b'<fin>'):
                nombre_archivo = data_descifrada[9:-5].decode()
            # Identificar la solicitud
            if data_descifrada == b"El archivo esta cifrado":
                respuesta = firmar_peticion_clave("dame la clave", clave_privada).encode()
                cliente_socket.send(cifrador(respuesta, key_simetrica))
                
            elif es_clave_aes_valida(data_descifrada):
                
                try:
                    with open('carpeta_del_cliente/contenido_recibido_' + nombre_archivo, 'rb') as archivo:
                        contenido_cifrado = archivo.read()
                        print("aqui esta el problema")
                        #contenido_descifrado = decifrador(contenido_cifrado, clave_descifrada)
                    with open('carpeta_del_cliente/contenido_descifrado_'+ nombre_archivo, 'wb') as archivo_descifrado:
                        
                        archivo_descifrado.write(contenido_descifrado)
                        
                        
                        
                except Exception as e:
                    cliente_socket.send(f"Error al descifrar: {e}".encode())

            else:
                cliente_socket.send(b"Comando no reconocido")

        except ConnectionResetError:
            break

    cliente_socket.close()

# --- Bucle principal del servidor ---
while True:
    ready_to_read, _, _ = select.select(inputs, [], [])

    for sock in ready_to_read:
        if sock is server_socket:
            cliente_socket, cliente_direccion = server_socket.accept()
            print(f"Cliente conectado desde {cliente_direccion}")
            hilo_cliente = threading.Thread(target=manejar_cliente, args=(cliente_socket,))
            hilo_cliente.start()
        else:
            try:
                data = sock.recv(1024)
                if data:
                    print(f"Datos recibidos en socket no principal: {data}")
            except ConnectionResetError:
                inputs.remove(sock)

server_socket.close()