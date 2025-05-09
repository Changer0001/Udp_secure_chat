"""
hmac_utils.py

Provides HMAC generation and verification utilities for message authentication in the secure UDP chat application.
Uses HMAC with SHA-256 for ensuring message integrity and authenticity.

Author: Burak Yilmaz
"""

import hmac  # For HMAC generation
import hashlib  # For SHA-256 hashing algorithm

def generate_hmac(secret_key, message):
    """
    Generates an HMAC for a given message using a secret key.

    Args:
        secret_key (bytes): The shared secret key used to generate the HMAC.
        message (str): The plaintext message to authenticate.

    Returns:
        str: The generated HMAC as a hexadecimal string.
    """
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(secret_key, message, received_hmac):
    """
    Verifies that the received HMAC matches the expected HMAC for the message.

    Args:
        secret_key (bytes): The shared secret key used to verify the HMAC.
        message (str): The plaintext message that was authenticated.
        received_hmac (str): The received HMAC to validate.

    Returns:
        bool: True if the received HMAC is valid; False otherwise.
    """
    expected_hmac = generate_hmac(secret_key, message)  # Recompute the HMAC for comparison
    return hmac.compare_digest(expected_hmac, received_hmac)  # Constant-time comparison to prevent timing attacks
