#!/usr/bin/env python3
"""_summary_
"""


import bcrypt


def _hash_password(password: str) -> bytes:
    """Generate a salted hash of the input password.

    Args:
           password (str): The password to hash.

    Returns:
           bytes: The salted hash of the password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
