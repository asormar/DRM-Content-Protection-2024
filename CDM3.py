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
    Imagen = Image.open(imagen).convert("RGBA")

    # Crear una nueva imagen de marca de agua en RGBA
    marca_agua = Image.new("RGBA", Imagen.size, (0, 0, 0, 0))
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
    marca_agua_rotada = Image.new("RGBA", Imagen.size, (0, 0, 0, 0))
    dibujar_rotada = ImageDraw.Draw(marca_agua_rotada)
    dibujar_rotada.text((x, y), texto_marca_agua, font=fuente, fill=color_relleno)

    # Rotar la marca de agua
    marca_agua_rotada = marca_agua_rotada.rotate(45, center=(x, y))

    # Combinar las imágenes usando alpha_composite
    resultado = Image.alpha_composite(Imagen, marca_agua_rotada)

    # Guardar la imagen final
    resultado.save(imagen)


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
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
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


def manejar_cliente(cliente_socket):
    file_bytes = b""
    procesar_imagen = False
    nombre_archivo = "archivo_recibido.jpg"  # Cambia según la extensión esperada.

    while True:
        try:
            data = cliente_socket.recv(1024)
            if not data:
                break

            data_descifrada = decifrador(data, key_simetrica)
            print(f"Datos descifrados: {data_descifrada}")

            if data_descifrada.startswith(b"<CONTENIDO>"):
                procesar_imagen = True
                print("Inicio de contenido detectado.")

            elif data_descifrada.endswith(b"<FIN>") and procesar_imagen:
                file_bytes += data_descifrada[:-5]
                ruta_archivo = f"carpeta_del_cliente/{nombre_archivo}"
                with open(ruta_archivo, "wb") as archivo:
                    archivo.write(file_bytes)
                print(f"Archivo recibido y guardado: {ruta_archivo}")
                procesar_imagen = False
                file_bytes = b""  # Reiniciar el buffer

                try:
                    marcar(ruta_archivo)
                    print(f"Marca de agua añadida a: {ruta_archivo}")
                except UnidentifiedImageError:
                    print("El archivo recibido no es una imagen válida.")

            elif procesar_imagen:
                file_bytes += data_descifrada

            else:
                print("Comando no reconocido.")

        except Exception as e:
            print(f"Error procesando cliente: {e}")
            break

    cliente_socket.close()

# --- Bucle principal del servidor ---
while True:
    try:
        ready_to_read, _, _ = select.select(inputs, [], [])

        for sock in ready_to_read:
            if sock is server_socket:
                cliente_socket, cliente_direccion = server_socket.accept()
                print(f"Cliente conectado desde {cliente_direccion}")
                hilo_cliente = threading.Thread(target=manejar_cliente, args=(cliente_socket,))
                hilo_cliente.daemon = True  # Hilos secundarios se cierran al terminar el servidor principal
                hilo_cliente.start()
            else:
                try:
                    data = sock.recv(1024)
                    if data:
                        print(f"Datos recibidos en socket no principal: {data}")
                except ConnectionResetError:
                    inputs.remove(sock)
    
    except KeyboardInterrupt:
        print("Servidor detenido manualmente.")
        break
    except Exception as e:
        print(f"Error inesperado en el servidor: {e}")

server_socket.close()
