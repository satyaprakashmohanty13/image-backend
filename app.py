from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io
import os
import base64
import struct

app = Flask(__name__)
CORS(app, origins=["https://satyaprakashmohanty13.github.io"])

# AES encrypt/decrypt helpers
def encrypt_message(message, password):
    key = password.ljust(32, '0')[:32].encode()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted

def decrypt_message(data, password):
    key = password.ljust(32, '0')[:32].encode()
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted) + unpadder.finalize()).decode()

# Hide message in LSB
def encode_image(image_bytes, message_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    pixels = list(image.getdata())
    bit_data = ''.join(f'{b:08b}' for b in struct.pack('>I', len(message_bytes)) + message_bytes)

    if len(bit_data) > len(pixels) * 3:
        raise ValueError("Message too long for this image.")

    new_pixels = []
    bit_index = 0
    for pixel in pixels:
        r, g, b = pixel
        if bit_index < len(bit_data):
            r = (r & ~1) | int(bit_data[bit_index])
            bit_index += 1
        if bit_index < len(bit_data):
            g = (g & ~1) | int(bit_data[bit_index])
            bit_index += 1
        if bit_index < len(bit_data):
            b = (b & ~1) | int(bit_data[bit_index])
            bit_index += 1
        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    output = io.BytesIO()
    image.save(output, format='PNG')
    output.seek(0)
    return output

def decode_image(image_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    pixels = list(image.getdata())

    bits = []
    for pixel in pixels:
        for color in pixel[:3]:
            bits.append(str(color & 1))

    byte_data = [int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8)]
    length = struct.unpack('>I', bytes(byte_data[:4]))[0]
    data = bytes(byte_data[4:4+length])
    return data

@app.route('/encode', methods=['POST'])
def encode():
    try:
        image_file = request.files['cover']
        message = request.form['message']
        password = request.form['password']
        encrypted = encrypt_message(message, password)
        result_image = encode_image(image_file.read(), encrypted)
        return send_file(result_image, mimetype='image/png')
    except Exception as e:
        return jsonify({'error': 'Encoding failed', 'detail': str(e)}), 500

@app.route('/decode', methods=['POST'])
def decode():
    try:
        image_file = request.files['stego']
        password = request.form['password']
        encrypted = decode_image(image_file.read())
        message = decrypt_message(encrypted, password)
        return jsonify({'message': message})
    except Exception as e:
        return jsonify({'error': 'Decoding failed', 'detail': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
