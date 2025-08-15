from __future__ import annotations

import logging

import ida_gdl
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from ida_funcs import func_t
    from ida_gdl import qbasic_block_t
    from ida_idaapi import ea_t

    from .database import Database


logger = logging.getLogger(__name__)


class _FlowChart(ida_gdl.FlowChart):
    """
    Flowchart class used to analyze and iterate through basic blocks within
    functions or address ranges.
    """

    def __init__(
        self, f: func_t = None, bounds: Optional[tuple[ea_t, ea_t]] = None, flags: int = 0
    ):
        super().__init__(f, bounds, flags)

    def _getitem(self, index: int) -> qbasic_block_t:
        """
        Internal method to access flowchart items by index.

        Args:
            index: The index of the basic block to retrieve.

        Returns:
            The basic block at the specified index.
        """
        return self._q[index]


@decorate_all_methods(check_db_open)
class BasicBlocks(DatabaseEntity):
    """
    Interface for working with basic blocks in functions.

    Basic blocks are sequences of instructions with a single entry point and single exit point,
    used for control flow analysis and optimization.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def get_instructions(self, block: qbasic_block_t) -> Optional[Iterator[insn_t]]:
        """
        Retrieves the instructions within a given basic block.

        Args:
            block: The basic block to analyze.

        Returns:
            An instruction iterator for the block.
        """
        return self.database.instructions.get_between(block.start_ea, block.end_ea)

    def get_from_function(self, func: func_t, flags: int = 0) -> _FlowChart:
        """
        Retrieves the basic blocks within a given function.

        Args:
            func: The function to retrieve basic blocks from.
            flags: Optional qflow_chart_t flags for flowchart generation (default: 0).

        Returns:
            An iterable flowchart containing the basic blocks of the function.
        """
        return _FlowChart(func, None, flags)

    def get_between(self, start_ea: ea_t, end_ea: ea_t, flags: int = 0) -> _FlowChart:
        """
        Retrieves the basic blocks within a given address range.

        Args:
            start_ea: The start address of the range.
            end_ea: The end address of the range.
            flags: Optional qflow_chart_t flags for flowchart generation (default: 0).

        Returns:
            An iterable flowchart containing the basic blocks within the specified range.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
            InvalidParameterError: If the input range is invalid.
        """

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        return _FlowChart(None, (start_ea, end_ea), flags)
