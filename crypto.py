# This is a simple encryption and decryption method in Python

# Import the necessary libraries
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define a function to encrypt a message
def encrypt(password, message):
  # Generate a random salt
  salt = os.urandom(16)

  # Derive the encryption key from the password and salt
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
  )
  key = base64.urlsafe_b64encode(kdf.derive(password))

  # Create a Fernet object using the derived key
  fernet = Fernet(key)

  # Encrypt the message and return the encrypted message and salt
  encrypted = fernet.encrypt(message)
  return encrypted, salt

# Define a function to decrypt a message
def decrypt(password, encrypted, salt):
  # Derive the decryption key from the password and salt
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
  )
  key = base64.urlsafe_b64encode(kdf.derive(password))

  # Create a Fernet object using the derived key
  fernet = Fernet(key)

  # Decrypt the message and return the decrypted message
  decrypted = fernet.decrypt(encrypted)
  return decrypted

# Test the encryption and decryption methods
password = "my_secret_password"
message = "This is a secret message"

encrypted, salt = encrypt(password, message)
decrypted = decrypt(password, encrypted, salt)

print(decrypted)  # This should print the original message
