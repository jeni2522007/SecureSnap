
import os
from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def encrypt_image(file_path, encrypted_folder):
    os.makedirs(encrypted_folder, exist_ok=True)

    key = generate_key()
    cipher = Fernet(key)

    with open(file_path, "rb") as file:
        image_data = file.read()

    encrypted_data = cipher.encrypt(image_data)

    encrypted_path = os.path.join(
        encrypted_folder,
        os.path.basename(file_path) + ".encrypted"
    )

    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)

    return encrypted_path, key.decode()


def decrypt_image(encrypted_path, key, output_path):
    cipher = Fernet(key.encode())

    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_path, "wb") as file:
        file.write(decrypted_data)

    return output_path
