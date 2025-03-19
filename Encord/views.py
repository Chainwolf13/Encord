import secrets

from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from .models import Message
from .forms import RegistrationForm

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
from django.http import JsonResponse
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import datetime


def index_view(request):
    if request.method == 'POST':
        username = request.POST.get('Username')
        password = request.POST.get('Password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            # User was authenticated
            # redirect to the index page upon successful login

            # login in the user
            login(request, user)
            return redirect('index')
        else:
            # User was not authenticated
            form = AuthenticationForm()
            return render(request, 'noUserFound.html')

    return render(request, 'logInPage.html')


def register_view(request):
    # This function renders the registration form page and create a new user based on the form data
    if request.method == 'POST':
        # We use Django's UserCreationForm which is a model created by Django to create a new user.
        # UserCreationForm has three fields by default: username (from the user model), password1, and password2.
        form = UserCreationForm(request.POST)
        # check whether it's valid: for example it verifies that password1 and password2 match
        if form.is_valid():
            form.save()
            # redirect the user to login page so that after registration the user can enter the credentials
            return redirect('login')
    else:
        # Create an empty instance of Django's UserCreationForm to generate the necessary html on the template.
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('Username')
        password = request.POST.get('Password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            # User was authenticated
            # redirect to the index page upon successful login

            # login in the user
            login(request, user)
            return redirect('messageHome')
        else:
            # User was not authenticated
            form = AuthenticationForm()
            return render(request, 'noUserFound.html')

    return render(request, 'logInPage.html')


# def message_view(request):
#     context = {}
#
#     # Generate AES key for Leon
#     leon_key = generate_aes_keys()
#     leon_message = f"Hey {request.user.username}, this is a demo so I will send you my private key so you can chat with me. Everything else will be encrypted so you will need it to talk with me from this point on."
#
#     # Encrypt Leon's message
#     encrypted_leon_message = encrypt_message(leon_message, leon_key)
#
#     # Store Leon's encrypted message in the database (optional)
#     Message.objects.create(MessageChat=encrypted_leon_message)
#
#     # Retrieve all messages
#     messages = Message.objects.all()
#     encrypted_messages = []
#     decrypted_messages = []
#     user_key = generate_aes_keys()  # Generate a key for the user messages
#
#     for message in messages:
#         encrypted_message = encrypt_message(message.MessageChat, user_key)
#         decrypted_message = decrypt_message(encrypted_message, user_key)
#
#         encrypted_messages.append(encrypted_message)
#         decrypted_messages.append(decrypted_message)
#
#     context['messages'] = zip(messages, encrypted_messages, decrypted_messages)
#     context['leon_message'] = encrypted_leon_message  # Send encrypted message to frontend
#     context['leon_key'] = b64encode(leon_key).decode('utf-8')  # Encode key for display
#
#     return render(request, 'messageHome.html', context)

def message_view(request):
    context = {}

    leon_message = f"Hey {request.user.username}, this is a demo so I will send you my private key so you can chat with me. Everything else will be encrypted, so you will need it to talk with me from this point on."

    # Encrypt Leon's message using his public key
    encrypted_leon_message = encrypt_with_rsa(leon_message, leon_public_key)

    # Store Leon’s encrypted message in the database (optional)
    Message.objects.create(MessageChat=encrypted_leon_message)

    context['leon_message'] = encrypted_leon_message
    context['leon_private_key'] = leon_private_pem  # Give the user Leon's private key

    return render(request, 'messageHome.html', context)



def logout_view(request):
    # Log out user
    logout(request)
    # Redirect to index with user logged out
    return redirect('index')


# Jahmaro Gordon -> method to encrypt message
# want to run command : pip install pycryptodome
def encrypt_message_to_database(message):
    # Generate AES key to encrypt message
    aes_key = generate_aes_keys()

    # Message to encrypt
    ciphermessage = encrypt_message(message, aes_key)
    # for debug
    # print("Encrypted message:", b64encode(ciphermessage).decode())

    # to decrypt
    decryptedmessage = decrypt_message(message, aes_key)
    # for debug
    # print("Decrypted message:", b64encode(ciphermessage).decode())

    return message


def generate_aes_keys():
    # this will generate a 256 bit AES key
    return secrets.token_bytes(32)


# This function will pad the message
def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    return padded_data


# This function encrypts a message with AES
def encrypt_message(message, key):
    # 128 bit IV
    iv = secrets.token_bytes(16)
    # algorithms.AES specifies that AES is used , key is going to be the AES key , MODE = CFB
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    # creates the encryptor object
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad_message(message)) + encryptor.finalize()
    # Convert the bytes to a Base64-encoded string
    encrypted_message = b64encode(iv + ciphertext).decode('utf-8')
    print(ciphertext)
    weird_encode = iv + ciphertext
    return iv + ciphertext


# Function to decrypt a message with AES
def decrypt_message(ciphertext, key):
    # get iv fron cipher text (extracts first 16 bits)
    iv = ciphertext[:16]
    # gets cipher text
    ciphertext = ciphertext[16:]
    # Creates a Cipher object from provided key, IV, and CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Performs the decryption by processing the ciphertext
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    # creates an unpadder for the PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    # Remove the padding to get the original message
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode('utf-8')


def decrypt_message_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            encrypted_message = b64decode(data.get("encrypted_message"))
            key = b64decode(data.get("key"))

            decrypted_message = decrypt_message(encrypted_message, key)
            return JsonResponse({"decrypted_message": decrypted_message})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)


# 6:17 PM 3/19/25

# Generate Leon's RSA key pair
leon_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

leon_public_key = leon_private_key.public_key()

# Export Leon's private key (to share with the user)
leon_private_pem = leon_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

# Export Leon's public key (for encrypting messages)
leon_public_pem = leon_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


def encrypt_with_rsa(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(encrypted_message).decode('utf-8')


def decrypt_with_rsa(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')


def decrypt_message_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            encrypted_message = data.get('encrypted_message')
            private_key_pem = data.get('key')

            if not private_key_pem:
                return JsonResponse({"error": "Private key required"}, status=400)

            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            decrypted_message = private_key.decrypt(
                bytes.fromhex(encrypted_message),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()

            return JsonResponse({"decrypted_message": decrypted_message})

        except Exception as e:
            return JsonResponse({"error": "Invalid decryption attempt"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

