from contextlib import contextmanager
from ctypes import wintypes
import ctypes

SYMBOL_FOLDER = "srv*c:\\symbols\\*http://msdl.microsoft.com/download/symbols"
MAX_SYM_NAME = 2000
DWORD64 = ctypes.c_ulonglong
NULL_PTR = ctypes.POINTER(DWORD64)()


class CantInitializeDebugHelperException(Exception):
    pass


class CantLoadDebugSymbolsException(Exception):
    pass


class PeAlreadyLoadedException(Exception):
    pass


class PeNotLoadedException(Exception):
    pass


class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", DWORD64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", DWORD64),
        ("Flags", wintypes.ULONG),
        ("Value", DWORD64),
        ("Address", DWORD64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.CHAR * MAX_SYM_NAME)
    ]


class PESymbolMatcher(object):
    def __init__(self):
        self._dbghelp = ctypes.windll.Dbghelp
        self._define_dbghelp_funcs()

        self._hproc = ctypes.windll.kernel32.GetCurrentProcess()
        self.loaded_pe = None
        self._loaded_pe_base_addr = 0

        ctypes.windll.kernel32.LoadLibraryW(r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symsrv.dll')

        if not self._dbghelp.SymInitializeW(self._hproc, SYMBOL_FOLDER, False):
            raise CantLoadDebugSymbolsException()

    def __del__(self):
        if self.loaded_pe:
            self.unload_pe()
        self._dbghelp.SymCleanup(self._hproc)

    # This is a trick to be able to use the class in a `with` statement without recreating the object everytime.
    # Not really sure if it is a recommended Python solution, but oh well - I'm a researcher not a developer.
    @contextmanager
    def __call__(self, pe_path: str) -> None:
        self.load_pe(pe_path)
        try:
            yield
        finally:
            if self.loaded_pe:
                self.unload_pe()

    def _define_dbghelp_funcs(self):
        self._dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.BOOL]
        self._dbghelp.SymInitializeW.restype = wintypes.BOOL
        self._dbghelp.SymLoadModuleExW.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.LPWSTR,
            DWORD64,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD
        ]
        self._dbghelp.SymLoadModuleExW.restype = DWORD64
        self._dbghelp.SymFromAddr.argtypes = [
            wintypes.HANDLE,
            DWORD64,
            ctypes.POINTER(DWORD64),
            ctypes.POINTER(SYMBOL_INFO)
        ]
        self._dbghelp.SymFromAddr.restype = wintypes.BOOL
        self._dbghelp.SymUnloadModule64.argtypes = [wintypes.HANDLE, DWORD64]
        self._dbghelp.SymUnloadModule64.restype = wintypes.BOOL
        self._dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]

        ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    def load_pe(self, pe_path: str) -> None:
        if self.loaded_pe:
            raise PeAlreadyLoadedException()
        self._loaded_pe_base_addr = self._dbghelp.SymLoadModuleExW(
            self._hproc,
            0,
            pe_path,
            ctypes.cast(NULL_PTR, wintypes.LPWSTR),
            0,
            0,
            0,
            0
        )
        if self._loaded_pe_base_addr:
            self.loaded_pe = pe_path
        else:
            print("failed loading PE", ctypes.windll.kernel32.GetLastError())

    def unload_pe(self) -> bool:
        self.assert_loaded_pe()
        if self._dbghelp.SymUnloadModule64(self._hproc, self._loaded_pe_base_addr):
            self.loaded_pe = None
            self._loaded_pe_base_addr = 0
            return True
        else:
            print("failed unloading", ctypes.windll.kernel32.GetLastError())
        return False

    def sym_from_addr(self, addr: int) -> str:
        sym_info = SYMBOL_INFO()
        sym_info.SizeOfStruct = ctypes.sizeof(SYMBOL_INFO) - MAX_SYM_NAME
        sym_info.MaxNameLen = MAX_SYM_NAME
        if not(self._dbghelp.SymFromAddr(self._hproc, DWORD64(addr), NULL_PTR, ctypes.byref(sym_info))):
            print(f"failed getting symbol for addr {hex(addr)}: {ctypes.windll.kernel32.GetLastError()}")
        return sym_info.Name.decode('ascii')

    def assert_loaded_pe(self):
        if not self.loaded_pe:
            raise PeNotLoadedException()
