#!/usr/bin/env python3
#
# SPLCrypt unpacker

# unpack IcedID/Bazarloader first stages
# author: Matthieu Walter (@matth_walter)
#

from arc4 import ARC4
import pefile
import yara
import sys
import re
import angr
import logging
import claripy
import itertools
from arc4 import ARC4
from malduck import u32, p32, xor

# pip install pyquicklz
import quicklz

# reduce logging verbosity
logging.getLogger('angr.storage').setLevel('ERROR')
logging.getLogger('angr.calling_conventions').setLevel('ERROR')
logging.getLogger('angr.analyses').setLevel('FATAL')
logging.getLogger('pyvex.lifting.libvex').setLevel('ERROR')


def get_section(pe, name):
    data = None
    for section in pe.sections:
        if section.Name.startswith(bytes(name, 'ascii') + b'\x00'):
            return section
    return None


def hook_api_hash(state):
    """ hook register calls with this
    """
    # symbolize return value
    state.regs.rax = claripy.BVS('ret', 64)
   

class PackerError(Exception):
    pass
    

class SPLCryptUnpacker:
    def __init__(self, filename):
        self.filename = filename
        
        try:
            self.pe = pefile.PE(filename)
        except pefile.PEFormatError as e:
            raise PackerError(str(e))

        self.marker = b'|SPL|'

        # 
        # 1. get data blobs / sanity check
        #
        self.raw_data = self.get_data_blobs()
        if not len(self.raw_data):
            raise PackerError("cannot extract data blob")


        # angr
        self.prj = angr.Project(filename, load_options={'auto_load_libs': False})
        self.cfg = self.prj.analyses.CFGFast()

        self.hooks = []


    def split(self, data):
        ''' split at marker
        '''
        return data.split(self.marker)


    def unpack(self):
        ''' process samples and returns a list of unpacked resources
        '''
        # sometimes there's no need to decrypt anything
        # ex: 2409da563ce216dee99fc9c016d5a2b1d8edcdfe5cc74ddf72fcb6ab5a5fdb3e
        for blob in self.raw_data:
            try:
                data = self.decompress(blob)
            except ValueError:
                continue

            if data is not None:
                print("apparently it wasn't encrypted...")
                return self.split(data)


        #
        # 2. get potential keys
        #
        potential_keys = self.find_key()

        if not len(potential_keys):
            raise PackerError("couldn't find any potential key")
        print("found %s potential keys: %r"%(len(potential_keys), potential_keys))


        #
        # 3. try to decrypt
        #
        for blob in self.raw_data:
            blob = self.try_to_decrypt(blob, potential_keys)
            if blob is not None:
                break

        if blob is None:
            raise PackerError("failed to decrypt")

        print("decrypted data: 0x%x bytes"%len(blob))


        #
        # 4. Split
        #
        return self.split(blob)


    def emulate(self, start_addr, stop_addr, max_iter=5000):
        """ symbolic execution from start_addr to stop_addr.
        max_iter is the maximum number of instructions

        return None if failed, or [r9]
        """
        print("emulating from 0x%x to 0x%x (max iter = %s)"%(start_addr, stop_addr, max_iter))
        state = self.prj.factory.call_state(addr=start_addr)

        # no function call
        state.options.add(angr.options.CALLLESS)

        simgr = self.prj.factory.simulation_manager(state)

        while True:
            # advance all states by one basic block
            simgr.step()
            max_iter -= 1

            # very arbitrary picks
            # we shouldnt run into too complex paths
            if not max_iter or len(simgr.active) > 10 or not len(simgr.active):
                return None

            # check each active
            for state in simgr.active:
                key = self.check_state(state, stop_addr)
                if key is not None:
                    return key

        return None


    def check_state(self, state, stop_addr):
        """ check if a state reached the expected address)
            hook potential call with unconstrained destinatinations

            returns the key if arrived at destination
        """

        # final destination
        #if state.addr in range(stop_addr, stop_addr+8):
        if state.addr == stop_addr:
            # dereference r9 register and read a DWORD
            # we assume the key is 4 bytes, we could read its size off the stack
            return p32(state.solver.eval(state.mem[state.regs.r9].uint32_t.resolved))
           

        #
        # hook registers calls (api hashing)
        # we want to hook all "call $tmp", otherwise angr gets lost
        # even with angr.options.CALLLESS
        #
        try:
            block = state.block()
        except angr.errors.SimEngineError:
            return None

        # verify that the block ends with a call
        if block.vex.jumpkind == 'Ijk_Call':
            # the next block is based on tmp value
            if block.vex.next.tag == 'Iex_RdTmp':
                # iterates over block instructions to find the call addr and size
                for insn in self.prj.factory.block(block.addr).capstone.insns:
                    if insn.mnemonic == 'call':
                        if insn.address not in self.hooks:
                            print("hooking addr=0x%x size=%s"%(insn.address, insn.size))
                            self.prj.hook(insn.address, hook_api_hash, length=insn.size)
                            # in order to avoid hook twice // angr would warn anyway
                            self.hooks.append(insn.address)
            
        return None


    def find_func_addr(self, addr):
        ''' given any instruction address
        returns the start address of the function it lives in
        '''
        function_addr = None

        # find function
        for node in self.cfg.graph.nodes():
            if addr in node.instruction_addrs:
                function_addr = node.function_address
                break

        # get function entry node
        # cfg.kb.functions.get_by_addr(addr)
        if function_addr is not None:
            for node in self.cfg.graph.nodes():
                if node.addr == function_addr:
                    return node

        return None



    def find_key(self):
        ''' find potential instructions setting the key
        '''
        # find .text
        section = get_section(self.pe, '.text')
        data = section.get_data()
    
        # oddly enough this seems to match the rc4 function
        # fairly accurately
        # like
        # 0x1800027c2      33c1                   xor     eax, ecx
        # 0x1800027c4      48634c2418             movsxd  rcx, dword [var_18h_2]
        # or
        # 0x180004242      0fb68c0cd0000000       movzx   ecx, byte [rsp + rcx + 0xd0]
        # 0x18000424a      33c1                   xor     eax, ecx
        # 0x18000424c      e974feffff             jmp     0x1800040c5 ; fcn.180003bbf+0x506
        rule = yara.compile(source="""
            rule rc4 {
                strings:
                    //$s1 = { 33 c1 }
                    $s2 = { 33 c1 48 63 4c 24 ?? }
                    $s3 = { 33 c1 (e9 | 3a) }
                condition:
                    $s2 or $s3
            }""")



        # get matching offsets
        yara_matches = rule.match(data=data)
        offsets = []

        if not len(yara_matches):
            raise PackerError("no yara match")

        for offset, _, _ in yara_matches[0].strings:
            # offset are relative to .text, rebase them
            off = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + offset
            offsets.append(off)

        # list of (start_addr, stop_addr) to emulate
        explorer = [] 

        # find callers
        for offset in offsets:
            func = self.find_func_addr(offset)
            if func is None:
                print("skip 0x%x: not part of a func..."%offset)
                continue

            if not len(func.predecessors):
                print("skip 0x%x: no predecessor..."%offset)
                continue
            
            if len(func.predecessors) > 2:
                print("skip 0x%s: too many predecessors (%d)"%(func.addr, len(func.predecessors)))
                continue


            print("found potential rc4 code: 0x%x"%func.addr)


            #1. caller_func
            #1.  start
            # ..
            #n. call rc4_func()
            # 
            #9. rc4_func
            # ..
            #m pattern match

            # 1. find pattern match offset
            # 2. find containing function (rc4_func / addr=9)
            # 3. find caller basic block (addr = n)
            # 4. find containing function (addr = 1)
            # 5. execute from 1 to n (caller start to call rc4)

            for pred in func.predecessors:
                caller = self.find_func_addr(pred.addr)
                # skip some cases where start_addr == stop_addr
                if caller is not None and caller.addr != pred.addr:
                    explorer.append((caller.addr, pred.addr))
                    print(" * found caller (0x%x -> 0x%x)"%(caller.addr, pred.addr))

        # emulate all potential calls
        potential_keys = []
        for start, stop in explorer:
            # emulate
            key = self.emulate(start, stop)
            if key:
                potential_keys.append(key)

        return set(potential_keys)


    def decompress(self, blob):
        ''' if header is right but later chunks were put in an incorrect
        order, there's a chance of segfault here
        '''
        try:
            return quicklz.decompress(blob)
        except:
            # try with a fixed blob ?
            blob = self._fix_blob(blob)
            if blob is not None:
                return quicklz.decompress(blob)
            raise ValueError


    def _fix_blob(self, blob):
        ''' in case of multiple blobs it seems there could be a few missing bytes
        we check that the quicklz compressed size header is 1 to 3 bytes smaller
        than the data we have and append the correct number of bytes from the marker
        '''
        diff = u32(blob[1:5]) - len(blob)
        if 0 < diff and diff < 3:
            return blob + self.marker[::-diff]
        return None


    def get_data_blobs(self):
        data = open(self.filename, 'rb').read()
        m = re.findall(rb'([0-9a-fA-F]{1000,})', data)
        if len(m):
            m = [str(_, 'ascii') for _ in m]
            # naive bazarloader handling where the data blob is split in 2 section
            # and merged
            # not really optimized or memory efficient....
            # sometimes there's like 1 byte of data which is not picked by the regex
            # just put something random so it doesnt crash, very dirty solution.
            # 
            # ex: 4a5f37ff394af7a750b1933c3e77b927043e933bfa715c917c824fbc645c940c
            # string[0] = &DAT_180051010;
            # string[1] = &DAT_180037000;
            # string[2] = &DAT_18001d000;
            # string[3] = &DAT_180051000;
            # string_size[0] = 0x1976f;
            # string_size[1] = 0x1976f;
            # string_size[2] = 0x1976f;
            # string_size[3] = 1;           <-- not picked by the regex

            dat = []
            # in case of multiple chunks, if the first one is in correct place
            # (ie: the header is right), but some later chunks are in the wrong
            # order, there's a possibility that quicklz segfaults...
            for d in sorted([''.join(_) for _ in itertools.permutations(m)]):
                # fix odd length
                # this is _fix_blob() are ugly work arounds...
                if len(d) % 2 != 0:
                    d += '0'
                dat.append(bytes.fromhex(d))
            return dat

        return []
    


    def try_to_decrypt(self, data, potential_keys):
        ''' try all keys with xor and without
             it seems the xor is not always applied
        '''
        for key in potential_keys:
            for apply_xor in [True, False]:
                print("trying key %r / xor=%r"%(key, apply_xor))
                dec = self.decrypt(data, key, apply_xor)
                if dec is not None:
                    return dec

        return None



    def decrypt(self, data, key, apply_xor):
        ''' decrypt + decompress data
        '''

        # RC4 decrypt
        cipher = ARC4(key)
        dec = bytearray(cipher.decrypt(data))

        # dexor
        if apply_xor:
            for x in range(len(dec) - 1):
                dec[x] = ((dec[x] ^ key[x % len(key)]) - dec[x + 1]) & 0xff

        # Quick check we got valid data
        # ref: quicklz format: https://github.com/ReSpeak/quicklz/blob/master/Format.md
        # DWORD at decrypted data+1 should be the length
        if u32(dec[1:5]) == len(data):
            return self.decompress(bytes(dec))
        # newer sample are not compressed
        if b'This program cannot be run in DOS mode.' in dec and dec.count(self.marker) > 1:
            return bytes(dec)

        return None



def extract_icedid_config(filename):
    pe = pefile.PE(filename)

    try:
        data = get_section(pe, ".d").get_data()
    except:
        return {}

    key = data[:0x20]
    conf = data[0x40:0x40+0x20]
    data = xor(key, conf)

    camp = u32(data[:4])
    c2 = data[4:].split(b'\x00')[0]

    return {'campaign_id': camp, 'c2': c2}



def error(msg):
    print("error: "+msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        print("%s <file>"%sys.argv[0])
        sys.exit(1)

    try:
        unpacker = SPLCryptUnpacker(sys.argv[1])
        files = unpacker.unpack()
        print("found %d elements"%len(files))
    except PackerError as e:
        error(str(e))

    for n, dat in enumerate(files):
        fname = sys.argv[1] + ".extracted.%d"%n
        with open(fname, 'wb') as fp:
            fp.write(dat)
            print("- dumped %s"%fname)
          
        # losy PE check
        if dat.startswith(b'MZ'):
            print("    looks like a PE... ", end='')
            print(extract_icedid_config(fname))


if __name__ == "__main__":
    main()
