from __future__ import annotations

import logging

import ida_bytes
import ida_ida
import ida_idaapi
import idc
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Heads(DatabaseEntity):
    """
    Provides access to heads (instructions or data items) in the IDA database.

    Can be used to iterate over all heads in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[ea_t]:
        return self.get_all()

    def get_all(self) -> Iterator[ea_t]:
        """
        Retrieves an iterator over all heads in the database.

        Returns:
            An iterator over the heads.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[ea_t]:
        """
        Retrieves all basic heads between two addresses.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range.

        Returns:
            An iterator over the heads.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        if not idc.is_head(ida_bytes.get_flags(ea)):
            ea = ida_bytes.next_head(ea, end_ea)
        while ea < end_ea and ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_head(ea, end_ea)

    def get_next(self, ea: ea_t) -> ea_t | None:
        """
        Retrieves the next head.

        Args:
            ea: Current head address.

        Returns:
            Next head, on error returns None.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        ea = ida_bytes.next_head(ea, ida_ida.inf_get_max_ea())
        return ea if ea != ida_idaapi.BADADDR else None

    def get_prev(self, ea: ea_t) -> ea_t | None:
        """
        Retrieves the prev head.

        Args:
            ea: Current head address.

        Returns:
            Prev head, on error returns None.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        ea = ida_bytes.prev_head(ea, ida_ida.inf_get_min_ea())
        return ea if ea != ida_idaapi.BADADDR else None
