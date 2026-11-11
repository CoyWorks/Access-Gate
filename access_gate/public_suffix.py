"""Offline public/private suffix checks using Ubuntu's maintained libpsl data."""
import ctypes
import ctypes.util
from .dns_export import hostname


class PublicSuffix:
    def __init__(self):
        library=ctypes.util.find_library('psl')
        if not library:raise ValueError('Install libpsl5 before starting the HTTPS gateway.')
        self.lib=ctypes.CDLL(library)
        self.lib.psl_builtin.restype=ctypes.c_void_p
        self.lib.psl_is_public_suffix.argtypes=(ctypes.c_void_p,ctypes.c_char_p)
        self.lib.psl_is_public_suffix.restype=ctypes.c_int
        self.context=self.lib.psl_builtin()
        if not self.context:raise ValueError('Public suffix data is unavailable; cannot issue wildcard certificates.')

    def safe_base(self,name):
        name=hostname(name)
        if len(name)>251:raise ValueError('The wildcard certificate base is too long.')
        if self.lib.psl_is_public_suffix(self.context,name.encode('ascii')):
            raise ValueError('A public/private suffix cannot be a wildcard certificate base.')
        return name
