from __future__ import annotations

import logging

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_typeinf
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .basic_blocks import _FlowChart

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Functions(DatabaseEntity):
    """
    Provides access to function-related operations within the IDA database.

    This class handles function discovery, analysis, manipulation, and provides
    access to function properties like names, signatures, basic blocks, and pseudocode.

    Can be used to iterate over all functions in the opened database.

    Args:
        database: Reference to the active IDA database.

    Note:
        Since this class does not manage the lifetime of IDA kernel objects (func_t*),
        it is recommended to use these pointers within a limited scope. Obtain the pointer,
        perform the necessary operations, and avoid retaining references beyond the
        immediate context to prevent potential issues with object invalidation.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[func_t]:
        return self.get_all()

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[func_t]:
        """
        Retrieves functions within the specified address range.

        Args:
            start_ea: Start address of the range (inclusive).
            end_ea: End address of the range (exclusive).

        Yields:
            Function objects whose start address falls within the specified range.

        Raises:
            InvalidEAError: If the start_ea/end_ea are specified but they are not
            in the database range.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue

            if func.start_ea >= end_ea:
                # Functions are typically ordered by address, so we can break early
                break

            if start_ea <= func.start_ea < end_ea:
                yield func

    def get_all(self) -> Iterator[func_t]:
        """
        Retrieves all functions in the database.

        Returns:
            An iterator over all functions in the database.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_at(self, ea: ea_t) -> Optional[func_t]:
        """
        Retrieves the function that contains the given address.

        Args:
            ea: An effective address within the function body.

        Returns:
            The function object containing the address,
            or None if no function exists at that address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.get_func(ea)

    def set_name(self, func: func_t, name: str, auto_correct: bool = True) -> bool:
        """
        Renames the given function.

        Args:
            func: The function instance.
            name: The new name to assign to the function.
            auto_correct: If True, allows IDA to replace invalid characters automatically.

        Returns:
            True if the function was successfully renamed, False otherwise.

        Raises:
            InvalidParameterError: If the name parameter is empty or invalid.
        """
        if not name.strip():
            raise InvalidParameterError('name', name, 'The name parameter cannot be empty')

        flags = ida_name.SN_NOCHECK if auto_correct else ida_name.SN_CHECK
        return ida_name.set_name(func.start_ea, name, flags)

    def get_basic_blocks(self, func: func_t) -> Optional[_FlowChart]:
        """
        Retrieves the basic blocks that compose the given function.

        Args:
            func: The function instance.

        Returns:
            An iterator over the function's basic blocks, or empty iterator if function is invalid.
        """
        return self.database.basic_blocks.get_from_function(func)

    def get_instructions(self, func: func_t) -> Optional[Iterator[insn_t]]:
        """
        Retrieves all instructions within the given function.

        Args:
            func: The function instance.

        Returns:
            An iterator over all instructions in the function,
            or empty iterator if function is invalid.
        """
        return self.database.instructions.get_between(func.start_ea, func.end_ea)

    def get_disassembly(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the disassembly lines for the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of disassembly.
            Returns empty list if function is invalid.
        """
        lines = []
        ea = func.start_ea

        options = ida_lines.GENDSM_MULTI_LINE
        if remove_tags:
            options |= ida_lines.GENDSM_REMOVE_TAGS

        while ea != BADADDR and ea < func.end_ea:
            line = ida_lines.generate_disasm_line(ea, options)
            if line:
                lines.append(line)

            ea = ida_bytes.next_head(ea, func.end_ea)

        return lines

    def get_pseudocode(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the decompiled pseudocode of the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of pseudocode. Returns empty list if
            function is invalid or decompilation fails.

        Raises:
            RuntimeError: If decompilation fails for the function.
        """
        # Attempt to decompile the function
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RuntimeError(f'Failed to decompile function at 0x{func.start_ea:x}')

        # Extract pseudocode lines
        pseudocode = []
        sv = cfunc.get_pseudocode()
        for i in range(len(sv)):
            line = sv[i].line
            if remove_tags:
                line = ida_lines.tag_remove(line)
            pseudocode.append(line)
        return pseudocode

    def get_microcode(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the microcode of the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of microcode. Returns empty list if
            function is invalid or decompilation fails.

        Raises:
            RuntimeError: If microcode generation fails for the function.
        """
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, ml, ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_GENERATED
        )

        if not mba:
            raise RuntimeError(f'Failed to generate microcode for function at 0x{func.start_ea:x}')

        mba.build_graph()
        total = mba.qty
        for i in range(total):
            if i == 0:
                continue

            block = mba.get_mblock(i)
            if block.type == ida_hexrays.BLT_STOP:
                continue

            vp = ida_hexrays.qstring_printer_t(None, True)
            block._print(vp)
            src = vp.s
            lines = src.splitlines()

            if not remove_tags:
                return lines

            microcode = []
            for line in lines:
                new_line = ida_lines.tag_remove(line)
                if new_line:
                    microcode.append(new_line)

            return microcode
        return []

    def get_signature(self, func: func_t) -> str:
        """
        Retrieves the function's type signature.

        Args:
            func: The function instance.

        Returns:
            The function signature as a string,
            or empty string if unavailable or function is invalid.
        """
        return ida_typeinf.idc_get_type(func.start_ea)

    def get_name(self, func: func_t) -> str:
        """
        Retrieves the function's name.

        Args:
            func: The function instance.

        Returns:
            The function name as a string, or empty string if no name is set.
        """
        name = self.database.names.get_at(func.start_ea)
        return name if name is not None else ''

    def create(self, ea: ea_t) -> bool:
        """
        Creates a new function at the specified address.

        Args:
            ea: The effective address where the function should start.

        Returns:
            True if the function was successfully created, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.add_func(ea)

    def remove(self, ea: ea_t) -> bool:
        """
        Removes the function at the specified address.

        Args:
            ea: The effective address of the function to remove.

        Returns:
            True if the function was successfully removed, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.del_func(ea)

    def get_callers(self, func: func_t) -> List[func_t]:
        """
        Gets all functions that call this function.

        Args:
            func: The function instance.

        Returns:
            List of calling functions.
        """
        callers: List[func_t] = []
        caller_addrs = set()  # Use set to avoid duplicates

        # Get all call references to this function
        for xref in self.database.xrefs.get_calls_to(func.start_ea):
            # Get the function containing this call site
            caller_func = self.get_at(xref.frm)
            if caller_func and caller_func.start_ea not in caller_addrs:
                caller_addrs.add(caller_func.start_ea)
                callers.append(caller_func)

        return callers

    def get_callees(self, func: func_t) -> List[func_t]:
        """
        Gets all functions called by this function.

        Args:
            func: The function instance.

        Returns:
            List of called functions.
        """
        callees: list[func_t] = []
        callee_addrs = set()  # Use set to avoid duplicates

        # Iterate through all instructions in the function to find calls and jumps
        for inst in self.database.instructions.get_between(func.start_ea, func.end_ea):
            # Get call references from this instruction
            for xref in self.database.xrefs.get_calls_from(inst.ea):
                # Get the target function
                target_func = self.get_at(xref.to)
                if target_func and target_func.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_func.start_ea != func.start_ea:
                        callee_addrs.add(target_func.start_ea)
                        callees.append(target_func)

            # Also get jump references for tail calls
            for xref in self.database.xrefs.get_jumps_from(inst.ea):
                # Get the target function
                target_func = self.get_at(xref.to)
                if target_func and target_func.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_func.start_ea != func.start_ea:
                        callee_addrs.add(target_func.start_ea)
                        callees.append(target_func)

        return callees
