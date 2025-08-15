from __future__ import annotations

import logging
from enum import Enum, IntEnum, IntFlag
from pathlib import Path

import ida_typeinf
from ida_typeinf import til_t, tinfo_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional, Union

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from ida_idaapi import ea_t

    from .database import Database


logger = logging.getLogger(__name__)


class LibraryAddFlags(IntFlag):
    """Flags for changing the way type libraries are added to the database"""

    ADD_DEFAULT = ida_typeinf.ADDTIL_DEFAULT
    """Default behavior"""
    ADD_INCOMPATIBLE = ida_typeinf.ADDTIL_INCOMP
    """Add incompatible type libraries"""
    ADD_SILENT = ida_typeinf.ADDTIL_SILENT
    """Do not ask any questions"""


class LibraryAddResult(IntEnum):
    """Return values for library add operation"""

    FAILED = ida_typeinf.ADDTIL_FAILED
    """Loading library failed"""
    SUCCESS = ida_typeinf.ADDTIL_OK
    """Library successfully loaded"""
    INCOMPATIBLE = ida_typeinf.ADDTIL_COMP
    """Library loaded but is incompatible"""
    ABORTED = ida_typeinf.ADDTIL_ABORTED
    """Library not loaded, rejected by the user"""


class TypeFormattingFlags(IntFlag):
    """Type formatting flags used to control type parsing, formatting and printing"""

    HTI_INT = ida_typeinf.HTI_INT
    """Debug: print internal representation of types"""
    HTI_EXT = ida_typeinf.HTI_EXT
    """Debug: print external representation of types"""
    HTI_LEX = ida_typeinf.HTI_LEX
    """Debug: print tokens"""
    HTI_UNP = ida_typeinf.HTI_UNP
    """Debug: check the result by unpacking it"""
    HTI_TST = ida_typeinf.HTI_TST
    """Test mode: discard the result"""
    HTI_FIL = ida_typeinf.HTI_FIL
    """"Input" is file name, otherwise "input" contains a C declaration"""
    HTI_MAC = ida_typeinf.HTI_MAC
    """Define macros from the base tils"""
    HTI_NWR = ida_typeinf.HTI_NWR
    """No warning messages"""
    HTI_NER = ida_typeinf.HTI_NER
    """Ignore all errors but display them"""
    HTI_DCL = ida_typeinf.HTI_DCL
    """Don't complain about redeclarations"""
    HTI_NDC = ida_typeinf.HTI_NDC
    """Don't decorate names"""
    HTI_PAK = ida_typeinf.HTI_PAK
    """Explicit structure pack value (#pragma pack)"""
    HTI_PAK_SHIFT = ida_typeinf.HTI_PAK_SHIFT
    """Shift for HTI_PAK. This field should be used if you want to remember
        an explicit pack value for each structure/union type.
        See HTI_PAK... definitions"""
    HTI_PAKDEF = ida_typeinf.HTI_PAKDEF
    """Default pack value"""
    HTI_PAK1 = ida_typeinf.HTI_PAK1
    """#pragma pack(1)"""
    HTI_PAK2 = ida_typeinf.HTI_PAK2
    """#pragma pack(2)"""
    HTI_PAK4 = ida_typeinf.HTI_PAK4
    """#pragma pack(4)"""
    HTI_PAK8 = ida_typeinf.HTI_PAK8
    """#pragma pack(8)"""
    HTI_PAK16 = ida_typeinf.HTI_PAK16
    """#pragma pack(16)"""
    HTI_HIGH = ida_typeinf.HTI_HIGH
    """Assume high level prototypes (with hidden args, etc)"""
    HTI_LOWER = ida_typeinf.HTI_LOWER
    """Lower the function prototypes"""
    HTI_RAWARGS = ida_typeinf.HTI_RAWARGS
    """Leave argument names unchanged (do not remove underscores)"""
    HTI_RELAXED = ida_typeinf.HTI_RELAXED
    """Accept references to unknown namespaces"""
    HTI_NOBASE = ida_typeinf.HTI_NOBASE
    """Do not inspect base tils"""
    HTI_SEMICOLON = ida_typeinf.HTI_SEMICOLON
    """Do not complain if the terminating semicolon is absent"""


class TypeKind(Enum):
    """Type category enumeration."""

    NAMED = 1
    NUMBERED = 2


@decorate_all_methods(check_db_open)
class Types(DatabaseEntity):
    """
    Provides access to type information and manipulation in the IDA database.

    Can be used to iterate over all types in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[ida_typeinf.tinfo_t]:
        return self.get_all()

    def load_library(self, file: Path) -> til_t:
        """
        Loads a type library file in memory.

        Args:
            file: The path of the library file to load.
                The library name can be passed with or without extension
                (.til extension will be forced) and as a relative (default ida
                til directory will be used) or absolute path.

        Returns:
            The loaded til_t object.
        """
        return ida_typeinf.load_til(str(file))

    def unload_library(self, library: til_t) -> None:
        """
        Unload library (free underlying object).

        Args:
            library: The library instance to unload.
        """
        ida_typeinf.free_til(library)

    def import_types_from_library(self, library: til_t) -> None:
        """
        Imports the types from an external library to the local (database) library.

        Args:
            library: The library instance to import from.

        Returns:
            The status of the add library operation.
        """
        for t in self.get_all(library=library):
            self.import_type(library, t.get_type_name())

    def export_types_to_library(self, library: til_t) -> None:
        """
        Export all types from local library to external library.
        Numbered types will be automatically enabled for the external library.

        Args:
            library: The destination library.
        """
        for t in self.get_all():
            self.export_type(library, t.get_type_name())

    def create_library(self, file: Path, description: str) -> til_t:
        """
        Initializes a new type library.

        Args:
            file: The name of the library.
            description: The description of the library.

        Returns:
            An initialized library.
        """
        return ida_typeinf.new_til(str(file.name), description)

    def save_library(self, library: til_t, file: Path) -> bool:
        """
        Stores the type library to a file.
        If the library contains garbage, it will be collected before storing it.
        Also compacts the library before saving.

        Args:
            library: The type library instance to save to disk.
            file: The path to save the library to.

        Returns:
            True if the operation succeeded, False otherwise.
        """
        ida_typeinf.compact_til(library)
        return ida_typeinf.store_til(library, str(file.parents), str(file))

    def import_type(self, source: til_t, name: str) -> int:
        """
        Imports a type and all dependent types from an external (loaded) library
        into the local (database) library.

        Args:
            source: The loaded type library from where to import the type.
            name: The name of the type.

        Raises:
            RuntimeError: If the import operation failed.

        Returns:
            The ordinal number of the imported type.
        """
        result = ida_typeinf.copy_named_type(ida_typeinf.get_idati(), source, name)
        if result == 0:
            raise RuntimeError(f'error importing type {name}')
        return result

    def export_type(self, destination: til_t, name: str) -> int:
        """
        Exports a type and all dependent types from the local (database) library
        into a loaded (external) library.

        Numbered types will be automatically enabled for the external library.

        Args:
            destination: The loaded type library from where to import the type.
            name: The name of the type.

        Raises:
            RuntimeError: If the export operation failed.

        Returns:
            The ordinal number of the imported type.
        """
        ida_typeinf.enable_numbered_types(destination, True)
        result = ida_typeinf.copy_named_type(destination, ida_typeinf.get_idati(), name)
        if result == 0:
            raise RuntimeError(f'error exporting type {name}')
        return result

    def copy_type(self, source: til_t, destination: til_t, name: str) -> int:
        """
        Copies a type and all dependent types from one library to another.

        Args:
            source: The source library.
            destination: The destination library.
            name: The name of the type.

        Raises:
            RuntimeError: If the copy operation failed.

        Returns:
            The ordinal number of the copied type.
        """
        result = ida_typeinf.copy_named_type(source, destination, name)
        if result == 0:
            raise RuntimeError(f'error exporting type {name}')
        return result

    def parse_header_file(
        self,
        library: til_t,
        header: Path,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_FIL | TypeFormattingFlags.HTI_PAKDEF,
    ) -> int:
        """
        Parse type declarations from file and store created types into a library.

        Args:
            library: The type library into where the parsed types will be stored.
            header: The path to a header file.
            flags: Optional combination of TypeFormattingFlags.

        Returns:
            Number of parse errors.
        """
        return ida_typeinf.parse_decls(library, header, None, flags)

    def parse_declarations(
        self,
        library: til_t,
        decl: str,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_DCL | TypeFormattingFlags.HTI_PAKDEF,
    ) -> int:
        """
        Parse type declarations from string and store created types into a library.

        Args:
            library: The type library into where the parsed types will be stored.
            decl: C type declarations input string.
            flags: Optional combination of TypeFormattingFlags.

        Returns:
            Number of parse errors.
        """
        return ida_typeinf.parse_decls(library, decl, None, flags)

    def get_type_name_at(self, ea: ea_t) -> str | None:
        """
        Retrieves the type information of the item at the given address.

        Args:
            ea: The effective address.

        Returns:
            The type name or None if it does not exist.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_typeinf.idc_get_type(ea)

    def apply_named_type_at(self, type: str, ea: ea_t) -> bool:
        """
        Applies a named type to the given address.

        Args:
            ea: The effective address.
            type: The name of the type to apply.

        Returns:
            True if the type was applied successfully, false otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_typeinf.apply_named_type(ea, type)

    def get_all(
        self, library: Optional[til_t] = None, type_kind: TypeKind = TypeKind.NAMED
    ) -> Iterator[ida_typeinf.tinfo_t]:
        """
        Retrieves an iterator over all types in the specified type library.

        Args:
            library: library instance to iterate over (defaults to local library).
            type_kind: type kind to iterate over (defaults to 'NAMED').

        Returns:
            A types iterator.
        """
        til = library
        if not til:
            til = ida_typeinf.get_idati()

        if type_kind == TypeKind.NAMED:
            yield from til.named_types()
        elif type_kind == TypeKind.NUMBERED:
            yield from til.numbered_types()
