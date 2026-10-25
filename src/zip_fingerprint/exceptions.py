"""Custom Exceptions for ZIP Fingerprinting."""

class ZipFingerprintError(Exception):
    """Base exception for zip-fingerprinting errors."""
    pass

class CorruptZipError(ZipFingerprintError):
    """Raised when a ZIP file is truncated, corrupt, or invalid."""
    pass

class UnsupportedZipFeatureError(ZipFingerprintError):
    """Raised when encountering an unsupported ZIP structure."""
    pass

