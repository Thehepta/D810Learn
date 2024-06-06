from d810.hexrays_formatters import format_mop_list
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
from typing import List, Union, Tuple

from d810.tracker import MopTracker
from utils import get_all_possibles_values
import logging


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

    def register_father(self, father: GenericDispatcherBlockInfo):
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




class GenericDispatcherInfo(object):
    def __init__(self, mba: mbl_array_t):
        self.mba = mba
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: mblock_t) -> bool:
        self.reset()

        self.entry_block = GenericDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)
        num_mop, self.mop_compared = self._get_comparison_info(self.entry_block.blk)
        self.comparison_values.append(num_mop.nnn.value)
        self._explore_children(self.entry_block)
        dispatcher_blk_with_external_father = self._get_dispatcher_blocks_with_external_father()
        # TODO: I think this can be wrong because we are too permissive in detection of dispatcher blocks
        if len(dispatcher_blk_with_external_father) != 0:
            return False
        return True
class GenericDispatcherCollector(minsn_visitor_t):
    DISPATCHER_CLASS = GenericDispatcherInfo

    def __init__(self):
        super().__init__()
        self.dispatcher_list = []
        self.explored_blk_serials = []
    def visit_minsn(self):
        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)
        disp_info = self.DISPATCHER_CLASS(self.blk.mba)
        is_good_candidate = disp_info.explore(self.blk)
        if not is_good_candidate:
            return 0
        if not self.specific_checks(disp_info):
            return 0
        self.dispatcher_list.append(disp_info)
        return 0

    def specific_checks(self, disp_info: GenericDispatcherInfo) -> bool:
        unflat_logger.debug("DispatcherInfo {0} : {1} internals, {2} exits, {3} comparison"
                            .format(self.blk.serial, len(disp_info.dispatcher_internal_blocks),
                                    len(disp_info.dispatcher_exit_blocks), len(set(disp_info.comparison_values))))
        if len(disp_info.dispatcher_internal_blocks) < self.dispatcher_min_internal_block:
            return False
        if len(disp_info.dispatcher_exit_blocks) < self.dispatcher_min_exit_block:
            return False
        if len(set(disp_info.comparison_values)) < self.dispatcher_min_comparison_value:
            return False
        self.dispatcher_list.append(disp_info)
        return True

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list

    def remove_sub_dispatchers(self):
        main_dispatcher_list = []
        for dispatcher_1 in self.dispatcher_list:
            is_dispatcher_1_sub_dispatcher = False
            for dispatcher_2 in self.dispatcher_list:
                if dispatcher_1.is_sub_dispatcher(dispatcher_2):
                    is_dispatcher_1_sub_dispatcher = True
                    break
            if not is_dispatcher_1_sub_dispatcher:
                main_dispatcher_list.append(dispatcher_1)
        self.dispatcher_list = [x for x in main_dispatcher_list]

class UnflattenerFakeJump(optblock_t):
    DISPATCHER_COLLECTOR_CLASS = GenericDispatcherCollector
    DEFAULT_MAX_PASSES = 5
    DEFAULT_MAX_DUPLICATION_PASSES = 20

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.non_significant_changes = 0


    def optimize(self, blk: mblock_t):
        self.mba = blk.mba
        self.last_pass_nb_patch_done = 0

        # blk.optimize_block()
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            unflat_logger.info("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        self.last_pass_nb_patch_done = self.remove_flattening()

        # nb_clean = mba_deep_cleaning(self.mba, False)
        return 0

    # def analyze_blk(self, blk: mblock_t) -> int:
    #
    #     op_compared = mop_t(blk.tail.l)
    #     blk_preset_list = [x for x in blk.predset]
    #     nb_change = 0
    #     for pred_serial in blk_preset_list:
    #         cmp_variable_tracker = MopTracker([op_compared], max_nb_block=100, max_path=1000)
    #         cmp_variable_tracker.reset()
    #         pred_blk = blk.mba.get_mblock(pred_serial)
    #         pred_histories = cmp_variable_tracker.search_backward(pred_blk, pred_blk.tail)
    #
    #         father_is_resolvable = all([father_history.is_resolved() for father_history in pred_histories])
    #         if not father_is_resolvable:
    #             return 0
    #         pred_values = get_all_possibles_values(pred_histories, [op_compared])
    #         pred_values = [x[0] for x in pred_values]
    #         if None in pred_values:
    #             print("Some path are not resolved, can't fix jump")
    #             return 0
    #         print("Pred {0} has {1} possible path ({2} different cst): {3}"
    #                            .format(pred_blk.serial, len(pred_values), len(set(pred_values)), pred_values))
    #         if self.fix_successor(blk, pred_blk, pred_values):
    #             nb_change += 1
    #     return nb_change

    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def remove_flattening(self) -> int:
        for dispatcher_info in self.dispatcher_list:
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]