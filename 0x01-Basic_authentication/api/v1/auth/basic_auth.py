#!/usr/bin/env python3
"""
Basic authentication module.

This module defines a BasicAuth class for basic authentication.
"""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar, List


class BasicAuth(Auth):
    """
    BasicAuth class for basic authentication.
    Inherits from Auth and currently does not add any new functionality.
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for
        Basic Authentication.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 part of the Authorization header,
            or None if invalid.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 value from the Authorization header.

        Args:
            base64_authorization_header (str): The Base64 encoded string.

        Returns:
            str: The decoded value as a UTF-8 string, or None if invalid.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
             self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the user email and password from the Base64 decoded value.

        Args:
            decoded_base64_authorization_header (str): The decoded
            Base64 value.

        Returns:
            tuple: A tuple containing the user email and password,
            or (None, None) if invalid.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User: The User instance, or None if not found
            or password is invalid.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        user = User.search({'email': user_email})
        if not user:
            return None

        if not user[0].is_valid_password(user_pwd):
            return None

        return user[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request.

        Args:
            request: The Flask request object.

        Returns:
            User: The User instance, or None if not found
            or authentication fails.
        """
        if request is None:
            return None

        # Retrieve the Authorization header from the request
        authorization_header = request.headers.get('Authorization')

        # Extract the Base64 part of the Authorization header
        base64_header = self.extract_base64_authorization_header(
                authorization_header)

        # Decode the Base64 header to get user credentials
        decoded_header = self.decode_base64_authorization_header(base64_header)

        # Extract user credentials from the decoded header
        email, password = self.extract_user_credentials(decoded_header)

        # Get the User instance based on email and password
        user = self.user_object_from_credentials(email, password)

        return user
