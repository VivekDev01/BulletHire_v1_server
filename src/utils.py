import bcrypt
import base64

def pad_base64(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)


def generate_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password_hash(hashed_password: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))