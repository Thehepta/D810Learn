import ida_hexrays
import pydevd
import ida_kernwin
import idaapi
import idc
import ida_bytes
import ida_idaapi
from ida_hexrays import *
import logging

FAKE_LOOP_OPCODES = [m_jz, m_jnz,m_jg]

def format_minsn_t(ins: minsn_t) -> str:
    if ins is None:
        return "minsn_t is None"

    tmp = ins._print()
    pp_ins = "".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in tmp])
    return pp_ins



class UnflattenerOpt(optblock_t):
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2]


    def __init__(self, *args):
        super().__init__(*args)
        self.mba = None
        self.cur_maturity = MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES


    def func(self, blk):
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        if (blk.tail is None) or blk.tail.opcode not in FAKE_LOOP_OPCODES:
            return 0
        print(hex(blk.head.ea))
        # if blk.get_reginsn_qty() != 1:
        #     return 0
        # if blk.tail.r.t != mop_n:
        #     return 0
        # logging.info("Checking if block {0} is fake loop: {1}".format(blk.serial, format_minsn_t(blk.tail)))
        op_compared = mop_t(blk.tail.l)
        blk_preset_list = [x for x in blk.predset]
        nb_change = 0
        for pred_serial in blk_preset_list:
            pred_blk = blk.mba.get_mblock(pred_serial)
            # pred_values = get_all_possibles_values(pred_histories, [op_compared])

            logging.info("Pred {0} ".format(pred_blk.serial))
        return 0             # report the number of changes

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        return True



class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Optimize UnflattenerOpt"
    wanted_hotkey = ""
    comment = "Sample plugin of UnflattenerOpt"
    help = ""
    def init(self):
        if init_hexrays_plugin():
            self.optimizer = UnflattenerOpt()
            self.optimizer.install()
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        self.optimizer.remove()
    def run(self, arg):
        if arg == 1:
            return self.optimizer.remove()
        elif arg == 2:
            return self.optimizer.install()

# def PLUGIN_ENTRY():  #可以当插件用
#     # import pydevd_pycharm
#     # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
#     return my_plugin_t()


if __name__ == '__main__':      #也可以直接在脚本里执行
    optimizer = UnflattenerOpt()
    optimizer.install()