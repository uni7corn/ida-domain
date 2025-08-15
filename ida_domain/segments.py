from __future__ import annotations

import logging

import ida_bytes
import ida_segment
from ida_idaapi import ea_t
from ida_segment import segment_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Segments(DatabaseEntity):
    """
    Provides access to segment-related operations in the IDA database.

    Can be used to iterate over all segments in the opened database.

    Args:
        database: Reference to the active IDA database.

    Note:
        Since this class does not manage the lifetime of IDA kernel objects (segment_t*),
        it is recommended to use these pointers within a limited scope. Obtain the pointer,
        perform the necessary operations, and avoid retaining references beyond the
        immediate context to prevent potential issues with object invalidation.
    """

    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[segment_t]:
        return self.get_all()

    def get_at(self, ea: ea_t) -> Optional[segment_t]:
        """
        Retrieves the segment that contains the given address.

        Args:
            ea: The effective address to search.

        Returns:
            A pointer to the containing segment, or None if none found.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_segment.getseg(ea)

    def get_name(self, segment: segment_t) -> str:
        """
        Retrieves the name of the given segment.

        Args:
            segment: Pointer to the segment.

        Returns:
            The segment name as a string, or an empty string if unavailable.
        """
        return ida_segment.get_segm_name(segment)

    def set_name(self, segment: segment_t, name: str) -> bool:
        """
        Renames a segment.

        Args:
            segment: Pointer to the segment to rename.
            name: The new name to assign to the segment.

        Returns:
            True if the rename operation succeeded, False otherwise.
        """
        return ida_segment.set_segm_name(segment, name)

    def get_all(self) -> Iterator[segment_t]:
        """
        Retrieves an iterator over all segments in the database.

        Returns:
            A generator yielding all segments in the database.
        """
        for current_index in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(current_index)
            if seg:
                yield seg
