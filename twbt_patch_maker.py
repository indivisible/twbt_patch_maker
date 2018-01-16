#!/usr/bin/env python3

import hashlib
import xml.etree.ElementTree as ET
from itertools import islice

import r2pipe


render_lower_levels_patches = {
    'linux': {
        'before': ['push r15', 'movsx r15d, si'],
        'after': [0x41, 0xc6, 0x00, 0x00, 0xC3]
        },
    'darwin': {
        'before': ['push r15', 'push r14', 'push r13'],
        'after': [0x41, 0xc6, 0x00, 0x00, 0xC3]
        },
    'windows': {
        'before': [
            'mov qword [rsp + 8], rbx',
            'push rbp', 'push rsi',
            'push rdi', 'push r12'
            ],
        'after': [0x48, 0x8B, 0x44, 0x24, 0x28,  0xC6, 0x00, 0x00,  0xC3]
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
    def __init__(self, df_path, symbols_path, verbose=False):
        self.df_path = df_path
        self.symbols_path = symbols_path
        self.verbose = verbose
        self.r2 = r2pipe.open(self.df_path)
        self.symbols = self.get_symbol_table()
        self.df_platform = self.symbols.get('os-type')
        self.results = {}
        self.analyse_done = False

    def get_symbol_table(self):
        info = self.r2.cmdj('iIj')
        # windows uses a timestamp header
        if info['class'] == 'PE32+':
            value = self.r2.cmd('ik image_file_header.TimeDateStamp')
            tag = 'binary-timestamp'
        else:
            value = md5(self.df_path)
            tag = 'md5-hash'
        value = value.lower()
        root = ET.parse(self.symbols_path).getroot()
        for table in root:
            hash_tag = table.find(tag)
            if hash_tag is None:
                continue
            if hash_tag.get('value').lower() == value:
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
            if block_size > 0:
                op = buf.pop(0)
                next_addr = op['offset'] + op['size']
            else:
                op = buf.pop()
                next_addr = op['offset']
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

        self.find_load_multi_pdim()
        self.find_p_display()

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
            if self.df_platform == 'windows':
                ops = ops[:2]
            assert ops[-1]['type'] == 'call'
            sizes.append('+'.join(str(op['size']) for op in ops))

        self.results['p_advmode_render'] = list(zip(p_advmode_render, sizes))
        self.results['A_RENDER_UPDOWN'] = hex(render_updown)

        self.find_render_lower_levels()

        return self.results

    def analyse(self):
        if not self.analyse_done:
            print('Running analysis. This will take a few minutes.')
            if self.df_platform == 'windows':
                self.r2.cmd('aaa')
            else:
                self.r2.cmd('aa')
                self.r2.cmd('aar')
            print('Analysis done.')
            self.analyse_done = True

    def find_load_multi_pdim(self):
        # not needed for linux
        if self.df_platform not in ('windows', 'darwin'):
            return

        self.analyse()

        matches = self.r2.cmdj('/j Tileset not found')
        assert len(matches) == 1, 'Too many matches found'
        for data_ref in self.r2.cmdj('axtj {}'.format(matches[0]['offset'])):
            for op in self.disasm_iter(data_ref['from'], -100):
                xrefs = op.get('xrefs', [])
                for xref in xrefs:
                    if xref['type'] == 'CALL':
                        break
                else:
                    continue
                self.results['A_LOAD_MULTI_PDIM'] = hex(op['offset'])
                return op['offset']

    def find_p_display(self):
        # not needed for linux
        if self.df_platform not in ('windows', 'darwin'):
            return

        self.analyse()

        # 1st find the function with the SDL_GetTicks call at its beginning
        if self.df_platform == 'windows':
            get_ticks_symbol = 'sym.imp.SDL.dll_SDL_GetTicks'
        else:
            get_ticks_symbol = 'sym.imp.SDL_GetTicks'
        for ref in self.r2.cmdj('axtj ' + get_ticks_symbol):
            ops = self.disasm(ref['from'], -5)
            for op in ops:
                xrefs = op.get('xrefs', [])
                for xref in xrefs:
                    if xref['type'] == 'CALL':
                        break
                else:
                    continue
                start_addr = ref['from']
                break
            else:
                continue
            break
        else:
            raise ValueError('Could not find function for p_display!')

        # next we look for 2 calls in a row to SDL_SemPost,
        # followed by 2 non-SDL calls. We want that last call op
        sempost_calls = 0
        other_calls = 0

        def report(msg):
            if self.verbose:
                print('{} 0x{:x} {}'.format(msg, op['offset'], op['opcode']))

        for num, op in enumerate(self.disasm_iter(start_addr)):
            if num >= 1000:
                raise RuntimeError(
                        'got trapped investigating calls from {}'.format(
                            start_addr))
            if 'call' not in op['type']:
                continue
            opcode = op['opcode']
            if 'SDL_SemPost' in opcode:
                if other_calls:
                    sempost_calls = 0
                report('sempost')
                sempost_calls += 1
                other_calls = 0
            elif 'SDL_GetTicks' in opcode:
                report('getticks -- reset')
                sempost_calls = 0
                other_calls = 0
            else:
                report('not sempost')
                other_calls += 1
                if other_calls == 2 and sempost_calls >= 2:
                    self.results['p_display'] = (hex(op['offset']), op['size'])
                    break
        else:
            raise ValueError('Could not find address for p_display!')

    def find_render_lower_levels(self):
        is_win = self.df_platform == 'windows'
        if is_win:
            cmp_size = 7
        else:
            cmp_size = 5
        for match in self.r2.cmdj('/xj 00000030'):
            # looking for a 5 byte test instruction
            addr = match['offset'] - (cmp_size - 4)
            op = self.disasm(addr, 1)[0]
            if 'cmp' in op['type'] and '0x30000000' in op['opcode']:
                if is_win:
                    # disasm a bit more to ensure we get a properly decoded
                    # instruction
                    prev_op = self.disasm(addr, -10)[-1]
                    if 'jmp' not in prev_op['type']:
                        continue
                break
        else:
            raise ValueError('failed to find p_render_lower_levels')
        for op in self.disasm(addr, 5):
            if 'jmp' in op['type']:
                addr = op['jump']
                break
        else:
            raise ValueError('failed to find p_render_lower_levels')
        op_type = 'call'
        if is_win:
            op_type = 'jmp'
        for op in self.filter_by_type(self.disasm(addr, 30), op_type):
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
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('df_exe')
    parser.add_argument('symbols_xml')

    args = parser.parse_args()

    patcher = TWBTPatchMaker(args.df_exe, args.symbols_xml, args.verbose)

    patcher.make_patch()
    patcher.print_patch()
    patcher.check_patch()

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
