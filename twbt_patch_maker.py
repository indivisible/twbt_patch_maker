#!/usr/bin/env python3

import hashlib
import xml.etree.ElementTree as ET
from itertools import islice

import r2pipe


render_lower_levels_patches = {
    'linux': {
        'before': ['push r15', 'movsx r15d, si'],
        'after': [0x41, 0xc6, 0x00, 0x00, 0xC3]
        }
    }


def md5(path, block_size=2**20):
    hash = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            hash.update(block)
    return hash.hexdigest()


class TWBTPatchMaker:
    def __init__(self, df_path, symbols_path):
        self.df_path = df_path
        self.symbols_path = symbols_path
        self.symbols = self.get_symbol_table()
        self.df_platform = self.symbols.get('os-type')
        if self.df_platform != 'linux':
            raise RuntimeError(
                'Only linux binaries are supported for now (got {!r})'.format(
                    self.df_platform))
        self.r2 = r2pipe.open(self.df_path)
        self.results = {}

    def get_symbol_table(self):
        hash = md5(self.df_path)
        root = ET.parse(self.symbols_path).getroot()
        for table in root:
            hash_tag = table.find('md5-hash')
            if hash_tag is None:
                continue
            if hash_tag.get('value') == hash:
                return table

    def get_vtable(self, name):
        return self.symbols.find(
                'vtable-address[@name="{}"]'.format(name)
                ).get('value')

    def disasm_iter(self, start_addr, block_size=100):
        buf = []
        next_addr = start_addr
        while True:
            if not buf:
                buf += self.r2.cmdj(
                        'pdj {} @ {}'.format(block_size, next_addr))
            op = buf.pop(0)
            next_addr = hex(op['offset'] + op['size'])
            yield op

    def disasm(self, start, num_ops):
        return self.r2.cmdj('pdj {} @ {}'.format(num_ops, start))

    @staticmethod
    def filter_by_type(ops, op_type):
        return filter(lambda op: op['type'] == op_type, ops)

    def find_render(self, vt_name):
        addr = '{} + 16'.format(self.get_vtable(vt_name))
        render_addr = self.r2.cmdj('pxqj 64 @ {}'.format(addr))[0]
        return render_addr

    def make_patch(self):
        self.results = {}
        render_dwarf_addr = self.find_render('viewscreen_dwarfmodest')
        for op in self.disasm(render_dwarf_addr, 20):
            if op['type'] == 'call':
                render_main = op['jump']
                break
        else:
            raise ValueError('render_main not found')
        calls = self.filter_by_type(self.disasm(render_main, 100), 'call')
        op = list(islice(calls, 2))[-1]
        render_map = op['jump']
        self.results['A_RENDER_MAP'] = hex(render_map)
        self.results['p_dwarfmode_render'] = (hex(op['offset']), op['size'])

        render_advmode_addr = self.find_render('viewscreen_dungeonmodest')

        num_render_map_calls = 4
        p_advmode_render = []
        render_updown = None
        last_jump = None
        for op in self.filter_by_type(
                self.disasm_iter(render_advmode_addr),
                'call'):
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

        sizes = []
        for addr in p_advmode_render:
            ops = self.disasm(addr, 3)
            sizes.append('+'.join(str(op['size']) for op in ops))

        self.results['p_advmode_render'] = list(zip(p_advmode_render, sizes))
        self.results['A_RENDER_UPDOWN'] = hex(render_updown)

        self.find_render_lower_levels()

        return self.results

    def find_render_lower_levels(self):
        for match in self.r2.cmdj('/xj 00000030'):
            # looking for a 5 byte test instruction
            addr = match['offset'] - 1
            ops = self.r2.cmdj('pdj 1 @ {}'.format(addr))
            op = ops[0]
            if 'cmp' in op['type'] and '0x30000000' in op['opcode']:
                break
        else:
            raise ValueError('failed to find p_render_lower_levels')
        for op in self.disasm(addr, 5):
            if 'jmp' in op['type']:
                addr = op['jump']
                break
        else:
            raise ValueError('failed to find p_render_lower_levels')
        for op in self.filter_by_type(self.disasm(addr, 30), 'call'):
            patch = render_lower_levels_patches[self.df_platform]['after']
            self.results['p_render_lower_levels'] = (hex(op['jump']), patch)
            return op['jump']

        raise ValueError('failed to find p_render_lower_levels')

    def check_render_lower_levels(self):
        addr = self.results['p_render_lower_levels'][0]
        known_ops = render_lower_levels_patches[self.df_platform]['before']
        ops = self.disasm(addr, len(known_ops))
        opcodes = [op['opcode'] for op in ops]
        if opcodes != known_ops:
            print(
                'Unkown sequence at p_render_lower_levels ({}):'.format(addr))
            print('Expected:')
            for op in known_ops:
                print('  {}'.format(op))
            print('Got:')
            for op in opcodes:
                print('  {}'.format(op))

            raise ValueError('Unknown sequence at p_render_lower_levels')
        return True

    def check_patch(self):
        self.check_render_lower_levels()

    def print_patch(self, indent=' '*8):
        results = self.results.copy()

        def maybe_print(key, fmt, multi=None):
            if key in results:
                value = results[key]
                if multi:
                    sep, multi_fmt = multi
                    value = sep.join(multi_fmt.format(i) for i in value)
                print(indent + fmt.format(key=key, value=value, indent=indent))
                del results[key]

        for name in ['A_LOAD_MULTI_PDIM', 'A_RENDER_MAP', 'A_RENDER_UPDOWN']:
            maybe_print(name, '#define {key:18} {value}')

        if 'p_display' not in results:
            print(indent + '#define NO_DISPLAY_PATCH')

        print()

        for name in ['p_display', 'p_dwarfmode_render']:
            maybe_print(
                    name,
                    'static patchdef {key} = {{ {value[0]}, {value[1]} }};\n')

        maybe_print(
            'p_advmode_render',
            'static patchdef {key}[] = {{\n    {indent}{value}\n{indent}}};\n',
            (', ', '{{ {0[0]}, {0[1]} }}'))

        key = 'p_render_lower_levels'
        if key in results:
            addr, patch_bytes = results[key]
            patch_len = len(patch_bytes)
            patch = ', '.join('0x{:02x}'.format(i) for i in patch_bytes)
            print(indent + 'static patchdef {} = {{'.format(key))
            print(indent + '    {}, {}, true, {{ {} }}'.format(
                addr,
                patch_len,
                patch))
            print(indent + '};\n')
            del results[key]

        assert not results, 'Unkown fields in results!'


def main():
    import argparse

    parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('df_exe')
    parser.add_argument('symbols_xml')

    args = parser.parse_args()

    patcher = TWBTPatchMaker(args.df_exe, args.symbols_xml)

    patcher.make_patch()
    patcher.print_patch()
    patcher.check_patch()

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
