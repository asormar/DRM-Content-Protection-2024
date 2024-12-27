from socket import *
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from PIL import Image, ImageDraw, ImageFont
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
    
from PIL import Image, ImageDraw, ImageFont

def add_watermark(image_path, text,exit_path):
    # Abrir la imagen
    image = Image.open(image_path).convert("RGBA")
    
    # Crear una capa para la marca de agua
    watermark = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(watermark)
    
    # Configurar la fuente (usa una fuente genérica del sistema)
    font_size = int(min(image.size) * 0.05)  # Tamaño proporcional a la imagen
    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()
    
    # Obtener las dimensiones del texto usando textbbox
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
    
    # Posición del texto (esquina inferior derecha con margen)
    x = image.size[0] - text_width - 10
    y = image.size[1] - text_height - 10
    
    # Dibujar el fondo negro para la marca de agua (un rectángulo detrás del texto)
    margin = 5  # Margen entre el texto y el fondo
    draw.rectangle([x - margin, y - margin, x + text_width + margin, y + text_height + margin], fill=(0, 0, 0, 255))
    
    # Dibujar el texto sobre el fondo negro con transparencia
    draw.text((x, y), text, font=font, fill=(255, 255, 0, 128))  # Texto amarillo con transparencia
    
    # Combinar la imagen original con la marca de agua
    watermarked_image = Image.alpha_composite(image, watermark)
    watermarked_image.convert("RGB").save(exit_path, "PNG")

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

                    contenido_en_lista = os.listdir("carpeta_contenidos")
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
                    #imagenes
                    add_watermark("carpeta_contenidos/"+mensaje[24:]+".png", str(cliente.getpeername()),"carpeta_contenidos/"+mensaje[24:]+"_marcada.png")
                    with open("carpeta_contenidos/"+mensaje[24:]+"_marcada.png", "rb") as archivo:
                        
                        imagen = archivo.read()
                        
                        # Cifrar el contenido
                        img_cifrada = cifrador(imagen)                        
                        
                        socket.send("<IMAGEN>".encode())
                        socket.sendall(img_cifrada)
                        socket.send("<FIN>".encode())
                        print("imagen "+mensaje[24:]+".png enviada")


                        
                except FileNotFoundError:
                    socket.send(cifrador("Error: mensaje no reconocido".encode()))
