from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_ida
import ida_range
from d810.hexrays_formatters import format_mop_list
from d810.cfg_utils import mba_deep_cleaning
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop
from d810.optimizers.flow.flattening.generic import GenericDispatcherBlockInfo, GenericDispatcherUnflatteningRule
from d810.optimizers.flow.flattening.generic import GenericDispatcherInfo
from d810.optimizers.flow.flattening.unflattener import OllvmDispatcherCollector
from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, get_all_possibles_values, \
    NotDuplicableFatherException
from d810.tracker import MopHistory, MopTracker
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
import ida_hexrays as hr
import ida_kernwin as kw
import logging

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe,hr.m_jg, hr.m_jge, hr.m_jl, hr.m_jle]

class adjustOllvmDispatcherInfo(GenericDispatcherInfo):

    def explore(self, blk: mblock_t) -> bool:
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
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

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        # blk must be a condition branch with one numerical operand
        num_mop, mop_compared = self._get_comparison_info(blk)
        if (num_mop is None) or (mop_compared is None):
            return False
        # Its fathers are not conditional branch with this mop
        for father_serial in blk.predset:
            father_blk = self.mba.get_mblock(father_serial)
            father_num_mop, father_mop_compared = self._get_comparison_info(father_blk)
            if (father_num_mop is not None) and (father_mop_compared is not None):
                if mop_compared.equal_mops(father_mop_compared, hr.EQ_IGNSIZE):
                    return False
        return True

    def _get_comparison_info(self, blk: mblock_t) -> Tuple[mop_t, mop_t]:
        # We check if blk is a good candidate for dispatcher entry block: blk.tail must be a conditional branch
        if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return None, None
        # One operand must be numerical
        num_mop, mop_compared = extract_num_mop(blk.tail)
        if num_mop is None or mop_compared is None:
            return None, None
        return num_mop, mop_compared

    def is_part_of_dispatcher(self, block_info: GenericDispatcherBlockInfo) -> bool:
        is_ok = block_info.does_only_need(block_info.father.assume_def_list)
        if not is_ok:
            return False
        if (block_info.blk.tail is not None) and (block_info.blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return False
        return True

    def _explore_children(self, father_info: GenericDispatcherBlockInfo):
        for child_serial in father_info.blk.succset:
            if child_serial in [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]:
                return
            if child_serial in [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]:
                return
            child_blk = self.mba.get_mblock(child_serial)
            child_info = GenericDispatcherBlockInfo(child_blk, father_info)
            child_info.parse()
            if not self.is_part_of_dispatcher(child_info):
                self.dispatcher_exit_blocks.append(child_info)
            else:
                self.dispatcher_internal_blocks.append(child_info)
                if child_info.comparison_value is not None:
                    self.comparison_values.append(child_info.comparison_value)
                self._explore_children(child_info)

    def _get_external_fathers(self, block_info: GenericDispatcherBlockInfo) -> List[mblock_t]:
        internal_serials = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        external_fathers = []
        for blk_father in block_info.blk.predset:
            if blk_father not in internal_serials:
                external_fathers.append(blk_father)
        return external_fathers

    def _get_dispatcher_blocks_with_external_father(self) -> List[mblock_t]:
        dispatcher_blocks_with_external_father = []
        for blk_info in self.dispatcher_internal_blocks:
            if blk_info.blk.serial != self.entry_block.blk.serial:
                external_fathers = self._get_external_fathers(blk_info)
                if len(external_fathers) > 0:
                    dispatcher_blocks_with_external_father.append(blk_info)
        return dispatcher_blocks_with_external_father





class adjustOllvmDispatcherCollector():
    DISPATCHER_CLASS = adjustOllvmDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 3
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2

    def __init__(self):
        super().__init__()
        self.dispatcher_list = []
        self.explored_blk_serials = []
        self.dispatcher_min_internal_block = self.DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK
        self.dispatcher_min_exit_block = self.DEFAULT_DISPATCHER_MIN_EXIT_BLOCK
        self.dispatcher_min_comparison_value = self.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        # self.remove_sub_dispatchers()
        return self.dispatcher_list

    def collector(self, mba):
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk.serial == 2:
                disp_info = self.DISPATCHER_CLASS(blk.mba)
                if True == disp_info.explore(blk):
                    self.dispatcher_list.append(disp_info)


class UnflattenerFakeJump(GenericDispatcherUnflatteningRule):
    DISPATCHER_COLLECTOR_CLASS = adjustOllvmDispatcherCollector
    DEFAULT_MAX_PASSES = 5
    DEFAULT_MAX_DUPLICATION_PASSES = 20

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.non_significant_changes = 0
        self.MOP_TRACKER_MAX_NB_BLOCK = 100
        self.MOP_TRACKER_MAX_NB_PATH = 100

    def func(self, blk: mblock_t):
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = 0
        logging.info("Unflattening at maturity {0} pass {1}".format(self.cur_maturity, self.cur_maturity_pass))
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            logging.info("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        else:
            logging.info("Unflattening: {0} dispatcher(s) found".format(len(self.dispatcher_list)))
            for dispatcher_info in self.dispatcher_list:
                dispatcher_info.print_info()
            self.last_pass_nb_patch_done = self.remove_flattening()
        logging.info("Unflattening at maturity {0} pass {1}: {2} changes"
                           .format(self.cur_maturity, self.cur_maturity_pass, self.last_pass_nb_patch_done))
        nb_clean = mba_deep_cleaning(self.mba, False)
        if self.last_pass_nb_patch_done + nb_clean + self.non_significant_changes > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
        self.mba.verify(True)
        return self.last_pass_nb_patch_done


    def start(self):
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        sel, sea, eea = kw.read_range_selection(None)
        pfn = ida_funcs.get_func(kw.get_screen_ea())
        if not sel and not pfn:
            return (False, "Position cursor within a function or select range")

        if not sel and pfn:
            sea = pfn.start_ea
            eea = pfn.end_ea
        print("fun addr:",hex(sea))
        addr_fmt = "%016x" if ida_ida.inf_is_64bit() else "%08x"
        fn_name = (ida_funcs.get_func_name(pfn.start_ea)
                   if pfn else "0x%s-0x%s" % (addr_fmt % sea, addr_fmt % eea))

        F = ida_bytes.get_flags(sea)
        if not ida_bytes.is_code(F):
            return (False, "The selected range must start with an instruction")
        text = "unfla"
        mmat = hr.MMAT_GLBOPT3
        if text is None and mmat is None:
            return (True, "Cancelled")

        if not sel and pfn:
            mbr = hr.mba_ranges_t(pfn)
        else:
            mbr = hr.mba_ranges_t()
            mbr.ranges.push_back(ida_range.range_t(sea, eea))

        hf = hr.hexrays_failure_t()
        ml = hr.mlist_t()
        #
        self.mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)

        self.retrieve_all_dispatchers()
        print("dispatcher_list = ",len(self.dispatcher_list))
        self.last_pass_nb_patch_done = self.remove_flattening()



    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.collector(self.mba)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def remove_flattening(self) -> int:
        total_nb_change = 0
        for dispatcher_info in self.dispatcher_list:
            print("dispatcher_info:",hex(dispatcher_info.entry_block.blk.start))
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(dispatcher_father,
                                                                                   dispatcher_info.entry_block)
                except NotDuplicableFatherException as e:
                    print(e)
                    pass


            for dispatcher_father in dispatcher_father_list:
                try:
                    self.resolve_dispatcher_father(dispatcher_father, dispatcher_info)
                except NotResolvableFatherException as e:
                    print("NotResolvableFatherException")

    def resolve_dispatcher_father(self, dispatcher_father: mblock_t, dispatcher_info):
        dispatcher_father_histories = self.get_dispatcher_father_histories(dispatcher_father,
                                                                           dispatcher_info.entry_block)
        # father_is_resolvable = self.check_if_histories_are_resolved(dispatcher_father_histories)
        # if not father_is_resolvable:
        #     raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))
        mop_searched_values_list = get_all_possibles_values(dispatcher_father_histories,
                                                            dispatcher_info.entry_block.use_before_def_list,
                                                            verbose=False)

        ref_mop_searched_values = mop_searched_values_list[0]
        print("entry_block:", dispatcher_father.serial)
        print("cvlist:", len(mop_searched_values_list))

        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException("Dispatcher {0} predecessor {1} is not resolvable: {2}"
                                                   .format(dispatcher_info.entry_block.serial, dispatcher_father.serial,
                                                           mop_searched_values_list))

            print("cv:",hex(tmp_mop_searched_values[0]))
        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(dispatcher_father_histories[0])
        if target_blk is not None:
            print("Unflattening graph: Making {0} goto {1}"
                                .format(dispatcher_father.serial, target_blk.serial))

    def get_dispatcher_father_histories(self, dispatcher_father: mblock_t,
                                        dispatcher_entry_block: GenericDispatcherBlockInfo) -> List[MopHistory]:
        father_tracker = MopTracker(dispatcher_entry_block.use_before_def_list,
                                    max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK, max_path=self.MOP_TRACKER_MAX_NB_PATH)
        father_tracker.reset()
        father_histories = father_tracker.search_backward(dispatcher_father, None)
        return father_histories

    def check_if_histories_are_resolved(self, mop_histories: List[MopHistory]) -> bool:
        return all([mop_history.is_resolved() for mop_history in mop_histories])



if __name__ == '__main__':      #也可以直接在脚本里执行
    try:
        optimizer = UnflattenerFakeJump()
        optimizer.start()
    except Exception as e:
        logging.exception(e)
