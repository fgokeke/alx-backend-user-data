#!/usr/bin/env python3
"""
Module for API authentication management.

This module defines a base Auth class to manage API authentication.
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    A class to manage API authentication.

    This class provides methods to manage authentication, including
    checking if a path requires authentication, getting the authorization
    header, and getting the current user.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that do
            not require authentication.

        Returns:
            bool: Always returns False for now.
        """
        if path is None:
            return True
        if not excluded_paths:
            return True

        normalized_path = path if path.endswith('/') else path + '/'

        if normalized_path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.

        Args:
            request: The Flask request object.

        Returns:
            str: Always returns None for now.
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.

        Args:
            request: The Flask request object.

        Returns:
            TypeVar('User'): Always returns None for now.
        """
        return None
