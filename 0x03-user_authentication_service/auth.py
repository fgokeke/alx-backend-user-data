#!/usr/bin/env python3
"""_summary_
"""


import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Generate a salted hash of the input password.

    Args:
           password (str): The password to hash.

    Returns:
           bytes: The salted hash of the password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user.

        Args:
            email (str): The email of the user to register.
            password (str): The password of the user to register.

        Returns:
            User: The newly registered User object.

        Raises:
            ValueError: If a user already exists with the passed email.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            pass

        hashed_password = _hash_password(password)
        user = self._db.add_user(email=email, hashed_password=hashed_password)
        return user
