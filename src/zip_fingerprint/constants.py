"""ZIP Format and Forensic Fingerprinting Constants.

Based on PKWARE APPNOTE and Minji Um et al. (2021).
"""

from enum import IntEnum

# Magic Signatures (Little-endian 4-byte integers)
SIG_LOCAL_FILE_HEADER = 0x04034B50
SIG_CENTRAL_DIRECTORY_HEADER = 0x02014B50
SIG_END_OF_CENTRAL_DIRECTORY = 0x06054B50
SIG_DATA_DESCRIPTOR = 0x08074B50
SIG_ZIP64_EOCD_RECORD = 0x06064B50
SIG_ZIP64_EOCD_LOCATOR = 0x07064B50

# Extra Field Header IDs (Paper Section 3.1 & Tables 1-5)
EXTRA_HEADER_NTFS = 0x000A          # NTFS extra field (64-bit FILETIME)
EXTRA_HEADER_EXTENDED_TS = 0x5455    # Extended timestamp (Unix 32-bit mtime/atime/ctime)
EXTRA_HEADER_UNIX_UID_GID = 0x7875   # Info-ZIP UNIX UID/GID (version 1)
EXTRA_HEADER_UNIX_5855 = 0x5855      # Info-ZIP Unix extra field (Bandizip on macOS)
EXTRA_HEADER_UNICODE_PATH = 0x7075   # Info-ZIP Unicode Path extra field (EFS flag)

# Host OS Byte Codes (Upper byte of version_made_by)
class HostOS(IntEnum):
    MSDOS_WINDOWS = 0
    AMIGA = 1
    OPENVMS = 2
    UNIX_LINUX = 3
    VM_CMS = 4
    ATARI = 5
    OS2_HPFS = 6
    MACINTOSH = 7
    Z_SYSTEM = 8
    CPM = 9
    WINDOWS_NTFS = 10
    MVS = 11
    VSE = 12
    ACORN_RISC = 13
    VFAT = 14
    ALTERNATE_MVS = 15
    BEOS = 16
    TANDEM = 17
    OS400 = 18
    OS_X = 19

# Default System UID / GID (Paper Section 3.1.2)
MACOS_DEFAULT_UID = 501
MACOS_DEFAULT_GID = 20
UBUNTU_DEFAULT_UID = 1000
UBUNTU_DEFAULT_GID = 1000

# Nanosecond Patterns in 0x000A NTFS Timestamp (Paper Section 3.1.1 & Table 6)
NANO_PATTERN_WINZIP = "fff0000"
NANO_PATTERN_FULL = "fffffff"
NANO_PATTERN_ZERO = "0000000"

