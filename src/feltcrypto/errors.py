"""Clear exception types used at parsing and trust boundaries """


class FeltCryptoError(Exception):
    """Base exception for the teaching library."""


class ParseError(FeltCryptoError, ValueError):
    """Input text was not valid in the requested representation."""


class PaddingError(FeltCryptoError, ValueError):
    """PKCS#7 padding was malformed."""


class UnknownLessonError(FeltCryptoError, KeyError):
    """A lesson id is not present in the registry."""


class AuthenticationError(FeltCryptoError):
    """Authenticated decryption failed and no plaintext is available."""
