#!/usr/bin/env python3
"""manage the API authentication"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ Basic Auth class
    """
    def extract_base64_authorization_header(self,
                                             authorization_header: str) -> str:
        """ Extract base64 authorization header
        """
        if authorization_header is None or\
              type(authorization_header) is not str:
            return None
        if authorization_header[:6] != 'Basic ':
            return None
        return authorization_header[6:]
    
    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """ returns the decoded value of a Base64 string base64_authorization_header
        """
        import base64
        if base64_authorization_header is None or\
              type(base64_authorization_header) is not str:
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None