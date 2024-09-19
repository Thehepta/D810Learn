import logging
from typing import List

from d810.hexrays_formatters import format_minsn_t, format_mop_list
from d810.hexrays_helpers import append_mop_if_not_in_list, get_mop_index, CONDITIONAL_JUMP_OPCODES, extract_num_mop
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.tracker import remove_segment_registers
from ida_hexrays import mop_t, minsn_t

unflat_logger = logging.getLogger('D810.unflat')


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
        self.ins = []
        self.use_list = []
        self.use_before_def_list = []
        self.def_list = []
        self.assume_def_list = []
        self.comparison_value = None
        self.compared_mop = None

        self.father = None
        if father is not None:
            self.register_father(father)

    @property
    def serial(self) -> int:
        return self.blk.serial

    def register_father(self, father: 'GenericDispatcherBlockInfo'):
        self.father = father
        self.assume_def_list = [x for x in father.assume_def_list]

    def update_use_def_lists(self, ins_mops_used: List[mop_t], ins_mops_def: List[mop_t]):
        for mop_used in ins_mops_used:
            append_mop_if_not_in_list(mop_used, self.use_list)
            mop_used_index = get_mop_index(mop_used, self.def_list)
            if mop_used_index == -1:
                append_mop_if_not_in_list(mop_used, self.use_before_def_list)
        for mop_def in ins_mops_def:
            append_mop_if_not_in_list(mop_def, self.def_list)

    def update_with_ins(self, ins: minsn_t):
        ins_mop_info = InstructionDefUseCollector()
        ins.for_all_ops(ins_mop_info)
        cleaned_unresolved_ins_mops = remove_segment_registers(ins_mop_info.unresolved_ins_mops)
        self.update_use_def_lists(cleaned_unresolved_ins_mops + ins_mop_info.memory_unresolved_ins_mops,
                                  ins_mop_info.target_mops)
        self.ins.append(ins)
        if ins.opcode in CONDITIONAL_JUMP_OPCODES:
            num_mop, other_mop = extract_num_mop(ins)
            if num_mop is not None:
                self.comparison_value = num_mop.nnn.value
                self.compared_mop = other_mop

    def parse(self):
        curins = self.blk.head
        while curins is not None:
            self.update_with_ins(curins)
            curins = curins.next
        for mop_def in self.def_list:
            append_mop_if_not_in_list(mop_def, self.assume_def_list)

    def does_only_need(self, prerequisite_mop_list: List[mop_t]) -> bool:
        for used_before_def_mop in self.use_before_def_list:
            mop_index = get_mop_index(used_before_def_mop, prerequisite_mop_list)
            if mop_index == -1:
                return False
        return True

    def recursive_get_father(self) -> List[GenericDispatcherBlockInfo]:
        if self.father is None:
            return [self]
        else:
            return self.father.recursive_get_father() + [self]

    def show_history(self):
        full_father_list = self.recursive_get_father()
        unflat_logger.info("    Show history of Block {0}".format(self.blk.serial))
        for father in full_father_list[:-1]:
            for ins in father.ins:
                unflat_logger.info("      {0}.{1}".format(father.blk.serial, format_minsn_t(ins)))

    def print_info(self):
        unflat_logger.info("Block {0} information:".format(self.blk.serial))
        unflat_logger.info("  USE list: {0}".format(format_mop_list(self.use_list)))
        unflat_logger.info("  DEF list: {0}".format(format_mop_list(self.def_list)))
        unflat_logger.info("  USE BEFORE DEF list: {0}".format(format_mop_list(self.use_before_def_list)))
        unflat_logger.info("  ASSUME DEF list: {0}".format(format_mop_list(self.assume_def_list)))

