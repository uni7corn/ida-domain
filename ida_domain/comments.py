from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from itertools import repeat

import ida_bytes
from ida_ida import inf_get_max_ea, inf_get_min_ea
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


class CommentKind(Enum):
    """
    Enumeration for IDA comment types.
    """

    REGULAR = 'regular'
    REPEATABLE = 'repeatable'
    ALL = 'all'


@dataclass(frozen=True)
class CommentInfo:
    """
    Represents information about a Comment.
    """

    ea: ea_t
    comment: str
    repeatable: bool


@decorate_all_methods(check_db_open)
class Comments(DatabaseEntity):
    """
    Provides access to user-defined comments in the IDA database.

    Can be used to iterate over all comments in the opened database.

    IDA supports two types of comments:
    - Regular comments: Displayed at specific addresses
    - Repeatable comments: Displayed at all references to the same address

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[CommentInfo]:
        return self.get_all()

    def get(self, ea: ea_t, comment_kind: CommentKind = CommentKind.REGULAR) -> CommentInfo | None:
        """
        Retrieves the comment at the specified address.

        Args:
            ea: The effective address.
            comment_kind: Type of comment to retrieve (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            The comment string, or None if no comment exists.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if comment_kind == CommentKind.ALL:
            # Try regular comment first, then repeatable
            for is_repeatable in [False, True]:
                comment = ida_bytes.get_cmt(ea, is_repeatable)
                if comment:
                    return CommentInfo(ea, comment, is_repeatable)
            return None

        # Handle REGULAR and REPEATABLE cases
        is_repeatable = comment_kind == CommentKind.REPEATABLE
        comment = ida_bytes.get_cmt(ea, is_repeatable)
        return CommentInfo(ea, comment, is_repeatable) if comment else None

    def get_any(self, ea: ea_t) -> CommentInfo | None:
        """
        Retrieves any comment at the specified address, checking both regular and repeatable.

        Args:
            ea: The effective address.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            A tuple (success, comment string). If no comment exists, success is False.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return self.get(ea, CommentKind.ALL)

    def set(self, ea: int, comment: str, comment_kind: CommentKind = CommentKind.REGULAR) -> bool:
        """
        Sets a comment at the specified address.

        Args:
            ea: The effective address.
            comment: The comment text to assign.
            comment_kind: Type of comment to set (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if the comment was successfully set, False otherwise.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        repeatable = comment_kind == CommentKind.REPEATABLE
        return ida_bytes.set_cmt(ea, comment, repeatable)

    def delete(self, ea: int, comment_kind: CommentKind = CommentKind.REGULAR) -> bool:
        """
        Deletes a comment at the specified address.

        Args:
            ea: The effective address.
            comment_kind: Type of comment to delete (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if the comment was successfully deleted, False otherwise.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        repeatable = comment_kind == CommentKind.REPEATABLE
        return ida_bytes.set_cmt(ea, '', repeatable)

    def get_all(self, comment_kind: CommentKind = CommentKind.REGULAR) -> Iterator[CommentInfo]:
        """
        Creates an iterator for comments in the database.

        Args:
            comment_kind: Type of comments to retrieve:
                - CommentKind.REGULAR: Only regular comments
                - CommentKind.REPEATABLE: Only repeatable comments
                - CommentKind.ALL: Both regular and repeatable comments

        Yields:
            Tuples of (address, comment_text, is_repeatable) for each comment found.
        """
        current = inf_get_min_ea()
        max_ea = inf_get_max_ea()

        while current < max_ea:
            # Check for regular comment
            if comment_kind in [CommentKind.REGULAR, CommentKind.ALL]:
                regular_comment = ida_bytes.get_cmt(current, False)
                if regular_comment:
                    yield CommentInfo(current, regular_comment, False)

            # Check for repeatable comment
            if comment_kind in [CommentKind.REPEATABLE, CommentKind.ALL]:
                repeatable_comment = ida_bytes.get_cmt(current, True)
                if repeatable_comment:
                    yield CommentInfo(current, repeatable_comment, True)

            # Move to next head (instruction or data)
            next_addr = ida_bytes.next_head(current, max_ea)
            if next_addr == current or next_addr == BADADDR:
                break
            current = next_addr
