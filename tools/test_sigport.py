#!/usr/bin/env python3
"""tools/sigport.py on two synthetic builds of one program.

Build A and build B have the same functions, globals, strings and float
constants at other addresses; B has an extra function in front, more
globals before the shared ones, and one function with an extra instruction.
Two functions are byte-for-byte twins (no unique hash): only their callers
tell them apart.

    .venv/bin/python tools/test_sigport.py
"""
import os, struct, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigport

# --- a tiny assembler: ops with symbolic operands -----------------------
def asm(ops, here, sym):
    out = bytearray()
    for op in ops:
        k = op[0]
        if k == 'prologue': out += b'\x55\x8b\xec'
        elif k == 'epilogue': out += b'\x5d\xc3'
        elif k == 'load': out += b'\xa1' + struct.pack('<I', sym[op[1]])          # mov eax,[g]
        elif k == 'store': out += b'\xa3' + struct.pack('<I', sym[op[1]])         # mov [g],eax
        elif k == 'lea': out += b'\xb9' + struct.pack('<I', sym[op[1]])           # mov ecx,offset
        elif k == 'push': out += b'\x68' + struct.pack('<I', sym[op[1]])          # push offset
        elif k == 'fld': out += b'\xd9\x05' + struct.pack('<I', sym[op[1]])       # fld dword [c]
        elif k == 'add': out += b'\x83\xc0' + bytes([op[1]])                      # add eax,imm8
        elif k == 'cmp': out += b'\x83\xf8' + bytes([op[1]])                      # cmp eax,imm8
        elif k == 'jz': out += b'\x74\x02'                                        # jz +2
        elif k == 'nop2': out += b'\x8b\xc0'                                      # mov eax,eax
        elif k == 'xor': out += b'\x33\xc0'                                       # xor eax,eax
        elif k == 'call':
            out += b'\xe8' + struct.pack('<i', sym[op[1]] - (here + len(out) + 5))
        elif k == 'mark': sym['@' + op[1]] = here + len(out)                      # a hook site
        else: raise ValueError(k)
    return bytes(out)

def build(funcs, order, globals_, strings, floats, text_va, data_va, rdata_va, extra_globals=0):
    sym = {}
    # data: globals, 16 bytes apart (a struct each)
    a = data_va + 16 * extra_globals
    for g in globals_: sym[g] = a; a += 16
    data = bytes(a - data_va)
    # rdata: strings, then floats
    rd = bytearray();
    for s, txt in strings.items():
        sym[s] = rdata_va + len(rd); rd += txt.encode() + b'\0'
        while len(rd) % 4: rd += b'\0'
    for c, v in floats.items():
        sym[c] = rdata_va + len(rd); rd += struct.pack('<f', v)
    # text: two passes (call targets); the first lays out with placeholders
    for f in order: sym.setdefault(f, text_va)
    for _ in range(2):
        t = bytearray()
        for f in order:
            while len(t) % 16: t += b'\xcc'
            sym[f] = text_va + len(t)
            t += asm(funcs[f], text_va + len(t), sym)
    return sigport.Image([('.text', text_va, bytes(t), True, False),
                          ('.rdata', rdata_va, bytes(rd), False, False),
                          ('.data', data_va, data, False, True)], entry=sym[order[0]]), sym

STR = {'s_hello': 'Hello, world', 's_car': 'CARS\\CAR.BIN', 's_fmt': 'value %d'}
FLT = {'c_half': 0.5, 'c_g': 9.81}
GLOB = ['g_timer', 'g_world', 'g_flags', 'g_input', 'g_cars']

def program(variant):
    f = {
        'main':    [('prologue',), ('call', 'init'), ('call', 'loop'), ('call', 'twin_user1'), ('call', 'twin_user2'), ('epilogue',)],
        'init':    [('prologue',), ('push', 's_hello'), ('call', 'log'), ('xor',), ('store', 'g_timer'), ('store', 'g_flags'), ('epilogue',)],
        'log':     [('prologue',), ('load', 'g_flags'), ('cmp', 1), ('jz',), ('nop2',), ('epilogue',)],
        'loop':    [('prologue',), ('call', 'step'), ('call', 'render'), ('load', 'g_timer'), ('add', 1), ('store', 'g_timer'), ('epilogue',)],
        'step':    [('prologue',), ('fld', 'c_g'), ('load', 'g_world'), ('mark', 'step_hook'), ('add', 4), ('store', 'g_world'),
                    ('lea', 'g_cars'), ('call', 'cars'), ('epilogue',)],
        'render':  [('prologue',), ('fld', 'c_half'), ('push', 's_fmt'), ('call', 'log'), ('load', 'g_input'), ('epilogue',)],
        'cars':    [('prologue',), ('push', 's_car'), ('call', 'log'), ('load', 'g_cars'), ('add', 8), ('epilogue',)],
        # twins: the same bytes, told apart by who calls them
        'twin_a':  [('prologue',), ('xor',), ('add', 3), ('epilogue',)],
        'twin_b':  [('prologue',), ('xor',), ('add', 3), ('epilogue',)],
        'twin_user1': [('prologue',), ('load', 'g_input'), ('call', 'twin_a'), ('add', 1), ('epilogue',)],
        'twin_user2': [('prologue',), ('load', 'g_world'), ('call', 'twin_b'), ('add', 2), ('epilogue',)],
    }
    order = ['main', 'init', 'log', 'loop', 'step', 'render', 'cars', 'twin_a', 'twin_b', 'twin_user1', 'twin_user2']
    if variant == 'B':
        # MW: an extra function first, step() grew an instruction, other addresses
        f['newfeat'] = [('prologue',), ('push', 's_hello'), ('call', 'log'), ('epilogue',)]
        f['step'] = f['step'][:3] + [('nop2',)] + f['step'][3:]
        f['main'] = f['main'][:-1] + [('call', 'newfeat'), ('epilogue',)]
        order = ['main', 'newfeat'] + order[1:]
        return build(f, order, GLOB, STR, FLT, 0x00401000, 0x00900000, 0x00800000, extra_globals=7)
    return build(f, order, GLOB, STR, FLT, 0x00401000, 0x00840000, 0x00780000)


class SigportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ia, cls.sa), (ib, cls.sb) = program('A'), program('B')
        cls.A, cls.B = sigport.Analysis(ia), sigport.Analysis(ib)
        cls.P = sigport.Porter(cls.A, cls.B)
        cls.P.run([cls.sa[f] for f in ('step', 'twin_a', 'twin_b')])

    def test_functions_found(self):
        for f in ('main', 'init', 'log', 'loop', 'step', 'render', 'cars', 'twin_user1', 'twin_user2'):
            self.assertIn(self.sa[f], self.A.funcs, f)

    def test_every_function_ported(self):
        for f in ('main', 'init', 'log', 'loop', 'step', 'render', 'cars', 'twin_a', 'twin_b', 'twin_user1', 'twin_user2'):
            to, how, s = self.P.port('func', self.sa[f])
            self.assertEqual(to, self.sb[f], f"{f}: {how} {s}")

    def test_twins_need_callers(self):
        self.assertNotEqual(self.P.fmap[self.sa['twin_a']][1], 'exact')
        self.assertEqual(self.P.fmap[self.sa['twin_a']][1], 'call')

    def test_changed_function_by_call(self):
        self.assertEqual(self.P.fmap[self.sa['step']][1], 'call')

    def test_globals(self):
        for g in GLOB:
            to, how, s = self.P.port('data', self.sa[g])
            self.assertEqual(to, self.sb[g], f"{g}: {how}")
            self.assertEqual(how, 'data')

    def test_struct_field_near(self):
        to, how, s = self.P.port('data', self.sa['g_cars'] + 8)
        self.assertEqual(to, self.sb['g_cars'] + 8)
        self.assertTrue(how.startswith('near'))

    def test_strings_and_constants(self):
        for s in list(STR) + list(FLT):
            to, how, _ = self.P.port('data', self.sa[s])
            self.assertEqual(to, self.sb[s], s)

    def test_hook_site_moves_with_its_instruction(self):
        to, how, s = self.P.port('site', self.sa['@step_hook'])
        self.assertEqual(to, self.sb['@step_hook'], how)

    def test_owner(self):
        self.assertEqual(self.A.owner(self.sa['@step_hook']), self.sa['step'])

    def test_unknown_stays_unknown(self):
        to, how, _ = self.P.port('data', 0x00841000 + 0x10000)
        self.assertIsNone(to)


if __name__ == '__main__':
    unittest.main(verbosity=2)
