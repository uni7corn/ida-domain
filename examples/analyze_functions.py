#!/usr/bin/env python3
"""
Function analysis example for IDA Domain API.

This example demonstrates how to find and analyze functions in an IDA database.
"""

import argparse

import ida_domain
from ida_domain.database import IdaCommandOptions


def analyze_functions(db_path, pattern='main', max_results=10):
    """Find and analyze functions matching a pattern."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Find functions matching a pattern
        matching_functions = []
        for func in db.functions:
            func_name = db.functions.get_name(func)
            if pattern.lower() in func_name.lower():
                matching_functions.append((func, func_name))

        print(f"Found {len(matching_functions)} functions matching '{pattern}':")

        # Limit results if requested
        display_functions = (
            matching_functions[:max_results] if max_results > 0 else matching_functions
        )

        for func, name in display_functions:
            print(f'\nFunction: {name}')
            print(f'Address: {hex(func.start_ea)} - {hex(func.end_ea)}')

            # Get signature
            signature = db.functions.get_signature(func)
            print(f'Signature: {signature}')

            # Get basic blocks
            bb_count = 0
            for _ in db.functions.get_basic_blocks(func):
                bb_count += 1
            print(f'Basic blocks: {bb_count}')

            # Show first few lines of disassembly
            disasm = db.functions.get_disassembly(func)
            print('Disassembly (first 5 lines):')
            for line in disasm[:5]:
                print(f'  {line}')

        if max_results > 0 and len(matching_functions) > max_results:
            print(f'\n... (showing first {max_results} of {len(matching_functions)} matches)')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-p',
        '--pattern',
        default='main',
        help='Pattern to search for in function names (default: main)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=10,
        help='Maximum number of results to display (0 for all, default: 10)',
    )
    args = parser.parse_args()
    analyze_functions(args.input_file, args.pattern, args.max_results)


if __name__ == '__main__':
    main()
