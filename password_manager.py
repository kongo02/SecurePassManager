from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64


def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()


# Generate the key if it does not exist
if not os.path.exists("key.key"):
    write_key()

key = load_key()
master_pwd = input("What is the master password? ")

# Derive a 32-byte key from the master password using PBKDF2
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"some_salt_here",  # Use a constant salt for simplicity or secure storage for per-user salts
    iterations=100000,
    backend=default_backend(),
)
derived_key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
fer = Fernet(derived_key)


def view():
    try:
        with open("passwords.txt", "r") as f:
            for line in f.readlines():
                data = line.rstrip()
                user, password = data.split("|")
                print(
                    "User: "
                    + user
                    + " | Password: "
                    + str(fer.decrypt(password.encode()))
                )
    except Exception as e:
        print("An error occurred during decryption:", e)


def add():
    name = input("Account Name: ")
    pwd = input("Password: ")

    with open("passwords.txt", "a") as f:
        f.write(name + " | " + fer.encrypt(pwd.encode()).decode() + "\n")


while True:
    mode = input(
        "Would you like to add a new password or view existing ones (view/add), press q to quit: "
    ).lower()
    if mode == "q":
        break
    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid Mode: " + mode)
