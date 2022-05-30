#!/usr/bin/env python3
# unpack IcedID first stage
# author: Matthieu Walter (@matth_walter)

from arc4 import ARC4
import pefile
import yara
import sys
import re
import angr
import logging
import claripy
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
    

class IcedID1:
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(filename)

        # angr
        self.prj = angr.Project(filename, load_options={'auto_load_libs': False})
        self.cfg = self.prj.analyses.CFGFast()

        self.hooks = []



    def emulate(self, start_addr, stop_addr, max_iter=3000):
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
        finds = rule.match(data=data)
        offsets = []
        for find in finds['main'][0]['strings']:
            # offset are relative to .text, rebase them
            off = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + find['offset']
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

        return potential_keys

    def get_section_list(self):
        self.section_list = []

        for section in self.pe.sections:
            temp_section = section.Name.decode('utf-8').rstrip('\x00')
            if temp_section in ('.data', '.rdata') or 'dos' in temp_section:
                self.section_list.append(temp_section)            

    def get_data_blob(self):

        self.get_section_list()

        for section in self.section_list:
            data = get_section(self.pe, section).get_data()
            m = re.findall(rb'([0-9a-fA-F]{1000,})', data)
            if len(m):
                return bytes.fromhex(str(m[0], 'ascii'))
        raise Exception("cannot find data blob")
    


def try_to_decrypt(data, potential_keys):
    ''' try all keys with xor and without
        it seems the xor is not always applied
    '''
    for key in potential_keys:
        for apply_xor in [True, False]:
            print("trying key %r / xor=%r"%(key, apply_xor))
            dec = decrypt(data, key, apply_xor)
            if dec is not None:
                return dec

    return None



def decrypt(data, key, apply_xor):
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
        return quicklz.decompress(bytes(dec))



def extract_c2(filename):
    pe = pefile.PE(filename)

    data = get_section(pe, ".d").get_data()
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

    ice_ice_baby = IcedID1(sys.argv[1])

    #
    # 1. get data blob
    #
    data = ice_ice_baby.get_data_blob()
 
    if not len(data):
        error("cannot get data blob")
    print("got data blob: 0x%x bytes"%len(data))
    
    #
    # 2. get potential key
    #
    potential_keys = ice_ice_baby.find_key()
    if not len(potential_keys):
        error("couldnt find any potential key")
    print("found %s potential keys: %r"%(len(potential_keys), potential_keys))


    #
    # 3. try to decrypt
    #
    data = try_to_decrypt(data, potential_keys)

    if data is None:
        error("failed to decrypt")

    print("decrypted data: 0x%x bytes"%len(data))

    #
    # 4. split data / dump config
    #
    files = data.split(b'|SPL|')
    print("found %d elements"%len(files))

    for n, dat in enumerate(files):
        fname = sys.argv[1] + ".extracted.%d"%n
        with open(fname, 'wb') as fp:
            fp.write(dat)
            print("- dumped %s"%fname)
          
        # losy PE check
        if dat.startswith(b'MZ'):
            print("    looks like a PE... ", end='')
            print(extract_c2(fname))


if __name__ == "__main__":
    main()
