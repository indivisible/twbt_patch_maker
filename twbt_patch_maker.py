#!/usr/bin/env python3

import hashlib
import xml.etree.ElementTree as ET
from itertools import islice

import r2pipe


def md5(path, block_size=2**20):
    hash = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            hash.update(block)
    return hash.hexdigest()


def get_symbol_table(df_path, symbols_path):
    hash = md5(df_path)
    root = ET.parse(symbols_path).getroot()
    for table in root:
        hash_tag = table.find('md5-hash')
        if hash_tag is None:
            continue
        if hash_tag.get('value') == hash:
            return table


def get_vtable(table, name):
    return table.find('vtable-address[@name="{}"]'.format(name)).get('value')


def disasm_iter(r2, start_addr, block_size=100):
    buf = []
    next_addr = start_addr
    while True:
        if not buf:
            buf += r2.cmdj('pdj {} @ {}'.format(block_size, next_addr))
        op = buf.pop(0)
        next_addr = hex(op['offset'] + op['size'])
        yield op

def disasm(r2, start, num_ops):
    return r2.cmdj('pdj {} @ {}'.format(num_ops, start))


def filter_by_type(ops, op_type):
    return filter(lambda op: op['type'] == op_type, ops)


def find_render(r2, table, vt_name):
    addr = '{} + 16'.format(get_vtable(table, vt_name))
    render_addr = r2.cmdj('pxqj 64 @ {}'.format(addr))[0]
    return render_addr


def make_patch(r2, table):
    results = {}
    render_dwarf_addr = find_render(r2, table, 'viewscreen_dwarfmodest')
    for op in disasm(r2, render_dwarf_addr, 20):
        if op['type'] == 'call':
            render_main = op['jump']
            break
    else:
        raise ValueError('render_main not found')
    #print(hex(render_main))
    calls = filter_by_type(disasm(r2, render_main, 100), 'call')
    op = list(islice(calls, 2))[-1]
    render_map = op['jump']
    results['A_RENDER_MAP'] = hex(render_map)
    results['p_dwarfmode_render'] = (hex(op['offset']), op['size'])

    render_advmode_addr = find_render(r2, table, 'viewscreen_dungeonmodest')
    print(hex(render_advmode_addr))

    num_render_map_calls = 4
    p_advmode_render = []
    render_updown = None
    last_jump = None
    for op in filter_by_type(disasm_iter(r2, render_advmode_addr), 'call'):
        if op['jump'] == render_map:
            p_advmode_render.append(hex(op['offset']))
        if last_jump == render_map:
            if render_updown is None:
                render_updown = op['jump']
            else:
                assert render_updown == op['jump']
        last_jump = op['jump']
        if len(p_advmode_render) >= num_render_map_calls:
            break

    results['p_advmode_render'] = p_advmode_render
    results['A_RENDER_UPDOWN'] = hex(render_updown)

    return results


def find_render_lower_levels(r2, results):
    for match in r2.cmdj('/xj 00000030'):
        # looking for a 5 byte test instruction
        addr = match['offset'] - 1
        ops = r2.cmdj('pdj 1 @ {}'.format(addr))
        op = ops[0]
        if 'cmp' in op['type'] and '0x30000000' in op['opcode']:
            break
    else:
        raise ValueError('failed to find p_render_lower_levels')
    print(hex(addr))
    for op in disasm(r2, addr, 5):
        if 'jmp' in op['type']:
            addr = op['jump']
            break
    else:
        raise ValueError('failed to find p_render_lower_levels')
    print(hex(addr))
    for op in filter_by_type(disasm(r2, addr, 30), 'call'):
        results['p_render_lower_levels'] = hex(op['jump'])
        return op['jump']

    raise ValueError('failed to find p_render_lower_levels')


def main():
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #parser.add_argument('-a', '--arg', type=str, default='default', help='help')
    parser.add_argument('df_exe')
    parser.add_argument('symbols_xml')

    args = parser.parse_args()

    table = get_symbol_table(args.df_exe, args.symbols_xml)
    r2 = r2pipe.open(args.df_exe)
    results = make_patch(r2, table)
    find_render_lower_levels(r2, results)
    print(results)

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
