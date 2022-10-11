from scraper_exceptions import CantFindRDataSectionException, DotNetPeException, NoRpcImportException


from typing import Tuple, Dict
from pefile import PE


def ptr_to_rva(ptr: int, pe: PE) -> int:
    return ptr-pe.OPTIONAL_HEADER.ImageBase


def assert_dotnet_pe(pe: PE) -> None:
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
        # This is the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR data directory - which is used only in .NET applications.
        raise DotNetPeException()


def get_rdata_offset_size_rva(pe: PE) -> Tuple[int, int, int]:
    for section in pe.sections:
        if section.Name == b'.rdata\x00\x00':
            return section.PointerToRawData, section.SizeOfRawData, section.VirtualAddress
    raise CantFindRDataSectionException()


def get_rpcrt_imports(pe: PE) -> Dict[int, str]:
    imports = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
    delay_imports = getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', [])
    if not imports and not delay_imports:
        raise NoRpcImportException
    for imp in imports + delay_imports:
        if imp.dll.decode("ascii").lower() == "rpcrt4.dll":
            # Not interested in imports by ordinal
            return {f.address: f.name.decode("ascii") for f in imp.imports if f.name}
    raise NoRpcImportException()
