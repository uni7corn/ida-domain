from __future__ import annotations

import logging
from enum import Enum, IntEnum

import ida_bytes
import ida_xref
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, Union

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class CodeRefType(IntEnum):
    """Code reference types."""

    UNKNOWN = ida_xref.fl_U
    """Unknown - for compatibility with old versions"""
    CALL_FAR = ida_xref.fl_CF
    """Call Far - creates a function at referenced location"""
    CALL_NEAR = ida_xref.fl_CN
    """Call Near - creates a function at referenced location"""
    JUMP_FAR = ida_xref.fl_JF
    """Jump Far"""
    JUMP_NEAR = ida_xref.fl_JN
    """Jump Near"""
    USER_SPECIFIED = ida_xref.fl_USobsolete
    """User specified (obsolete)"""
    ORDINARY_FLOW = ida_xref.fl_F
    """Ordinary flow to next instruction"""


class DataRefType(IntEnum):
    """Data reference types."""

    UNKNOWN = ida_xref.dr_U
    """Unknown - for compatibility with old versions"""
    OFFSET = ida_xref.dr_O
    """Offset reference or OFFSET flag set"""
    WRITE = ida_xref.dr_W
    """Write access"""
    READ = ida_xref.dr_R
    """Read access"""
    TEXT = ida_xref.dr_T
    """Text (for forced operands only)"""
    INFORMATIONAL = ida_xref.dr_I
    """Informational reference"""
    SYMBOLIC = ida_xref.dr_S
    """Reference to enum member (symbolic constant)"""


# Human-readable type names mapping
_ref_types = {
    ida_xref.fl_U: 'Data_Unknown',
    ida_xref.dr_O: 'Data_Offset',
    ida_xref.dr_W: 'Data_Write',
    ida_xref.dr_R: 'Data_Read',
    ida_xref.dr_T: 'Data_Text',
    ida_xref.dr_I: 'Data_Informational',
    ida_xref.dr_S: 'Data_Symbolic',
    ida_xref.fl_CF: 'Code_Far_Call',
    ida_xref.fl_CN: 'Code_Near_Call',
    ida_xref.fl_JF: 'Code_Far_Jump',
    ida_xref.fl_JN: 'Code_Near_Jump',
    ida_xref.fl_USobsolete: 'Code_User_Specified',
    ida_xref.fl_F: 'Ordinary_Flow',
}


def is_call_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a call reference."""
    return xref_type in [CodeRefType.CALL_NEAR, CodeRefType.CALL_FAR]


def is_jump_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a jump reference."""
    return xref_type in [CodeRefType.JUMP_NEAR, CodeRefType.JUMP_FAR]


def is_code_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a code reference."""
    return xref_type in [
        CodeRefType.CALL_NEAR,
        CodeRefType.CALL_FAR,
        CodeRefType.JUMP_NEAR,
        CodeRefType.JUMP_FAR,
        CodeRefType.ORDINARY_FLOW,
        CodeRefType.USER_SPECIFIED,
    ]


def is_data_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data reference."""
    return xref_type in [
        DataRefType.OFFSET,
        DataRefType.WRITE,
        DataRefType.READ,
        DataRefType.TEXT,
        DataRefType.INFORMATIONAL,
        DataRefType.SYMBOLIC,
    ]


def is_read_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data read reference."""
    return xref_type == DataRefType.READ


def is_write_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data write reference."""
    return xref_type == DataRefType.WRITE


def is_offset_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is an offset reference."""
    return xref_type == DataRefType.OFFSET


def get_ref_type_name(xref_type: Union[int, CodeRefType, DataRefType]) -> str:
    """Get human-readable name for xref type."""
    return _ref_types.get(xref_type, 'Unknown')


class XrefsKind(Enum):
    """
    Enumeration for IDA Xrefs types.
    """

    CODE = 'code'
    DATA = 'data'
    ALL = 'all'


@decorate_all_methods(check_db_open)
class Xrefs(DatabaseEntity):
    """
    Provides access to cross-reference (xref) analysis in the IDA database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def get_to(
        self, ea: ea_t, kind: XrefsKind = XrefsKind.ALL, flow: bool = True
    ) -> Iterator[Any]:
        """
        Creates an iterator over all xrefs pointing to a given address.

        Args:
            ea: Target effective address.
            kind: Xrefs kind (defaults to XrefsKind.ALL).
            flow: Follow normal code flow or not (defaults to True).

        Returns:
            An iterator over references to input target addresses.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xref = ida_xref.xrefblk_t()
        if kind == XrefsKind.CODE:
            if flow:
                yield from xref.crefs_to(ea)
            else:
                yield from xref.fcrefs_to(ea)

        elif kind == XrefsKind.DATA:
            yield from xref.drefs_to(ea)

        elif kind == XrefsKind.ALL:
            success = xref.first_to(ea, ida_xref.XREF_ALL)

            while success:
                yield xref
                success = xref.next_to()

    def get_from(
        self, ea: ea_t, kind: XrefsKind = XrefsKind.ALL, flow: bool = False
    ) -> Iterator[Any]:
        """
        Creates an iterator over all xrefs originating from a given address.

        Args:
            ea: Source effective address.
            kind: Xrefs kind (defaults to XrefsKind.ALL).
            flow: Follow normal code flow or not (defaults to True).

        Returns:
            An iterator over outgoing xrefs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xref = ida_xref.xrefblk_t()
        if kind == XrefsKind.CODE:
            if flow:
                yield from xref.crefs_from(ea)
            else:
                yield from xref.fcrefs_from(ea)

        elif kind == XrefsKind.DATA:
            yield from xref.drefs_from(ea)

        elif kind == XrefsKind.ALL:
            success = xref.first_from(ea, ida_xref.XREF_ALL)

            while success:
                yield xref
                success = xref.next_from()

    def get_name(self, ref: ida_xref.xrefblk_t) -> str:
        """
        Get human-readable xref type name.

        Args:
            ref: A xref block.

        Returns:
            A human-readable xref type name.
        """
        return _ref_types.get(ref.type, 'Unknown')

    def get_calls_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all call references to the specified address.

        Args:
            ea: Target effective address.

        Returns:
            An iterator over call references to the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_call_ref(xref.type):
                yield xref

    def get_calls_from(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all call references from the specified address.

        Args:
            ea: Source effective address.

        Returns:
            An iterator over call references from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_from(ea, XrefsKind.ALL):
            if is_call_ref(xref.type):
                yield xref

    def get_jumps_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all jump references to the specified address.

        Args:
            ea: Target effective address.

        Returns:
            An iterator over jump references to the address.
        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_jump_ref(xref.type):
                yield xref

    def get_jumps_from(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all jump references from the specified address.

        Args:
            ea: Source effective address.

        Returns:
            An iterator over jump references from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_from(ea, XrefsKind.ALL):
            if is_jump_ref(xref.type):
                yield xref

    def get_data_reads_of(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all places that read data from the specified address.

        Args:
            ea: Target effective address (the data being read).

        Returns:
            An iterator over references that read data from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_read_ref(xref.type):
                yield xref

    def get_data_writes_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all places that write data to the specified address.

        Args:
            ea: Target effective address (the data being written to).

        Returns:
            An iterator over references that write data to the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_write_ref(xref.type):
                yield xref

    def is_call_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a call reference."""
        return is_call_ref(xref_type)

    def is_jump_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a jump reference."""
        return is_jump_ref(xref_type)

    def is_code_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a code reference."""
        return is_code_ref(xref_type)

    def is_data_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data reference."""
        return is_data_ref(xref_type)

    def is_read_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data read reference."""
        return is_read_ref(xref_type)

    def is_write_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data write reference."""
        return is_write_ref(xref_type)

    def is_offset_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is an offset reference."""
        return is_offset_ref(xref_type)

    def get_ref_type_name(self, xref_type: Union[int, CodeRefType, DataRefType]) -> str:
        """Get human-readable name for xref type."""
        return get_ref_type_name(xref_type)
