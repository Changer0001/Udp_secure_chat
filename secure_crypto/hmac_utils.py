import hmac
import hashlib

def generate_hmac(secret_key, message):
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(secret_key, message, received_hmac):
    expected_hmac = generate_hmac(secret_key, message)
    return hmac.compare_digest(expected_hmac, received_hmac)
