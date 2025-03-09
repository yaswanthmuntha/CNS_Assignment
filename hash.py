import hashlib
import os

def hash_password(password: str, salt: bytes = None) -> tuple:
    
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, hashed

def store_password(password: str) -> tuple:
    
    salt, hashed_password = hash_password(password)
    return salt.hex(), hashed_password.hex()

def verify_password(stored_salt: str, stored_hash: str, password_attempt: str) -> bool:
    
    salt = bytes.fromhex(stored_salt)
    _, new_hash = hash_password(password_attempt, salt)
    return new_hash.hex() == stored_hash


password = input("Enter a password to store: ")
salt, hashed_password = store_password(password)
print(f"Stored Salt: {salt}")
print(f"Stored Hash: {hashed_password}")

attempt = input("Enter password to verify: ")
if verify_password(salt, hashed_password, attempt):
    print("Password is correct!")
else:
    print("Incorrect password!")
