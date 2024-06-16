from typing import List

import ida_bytes
import ida_funcs
import ida_ida
import ida_range
from d810.hexrays_formatters import format_mop_list
from d810.hexrays_helpers import  append_mop_if_not_in_list
from d810.optimizers.flow.flattening.generic import GenericDispatcherBlockInfo
from d810.optimizers.flow.flattening.generic import GenericDispatcherInfo
from d810.optimizers.flow.flattening.unflattener import OllvmDispatcherCollector
from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, get_all_possibles_values
from d810.tracker import MopHistory, MopTracker
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
import ida_hexrays as hr
import ida_kernwin as kw
import logging


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
class adjustOllvmDispatcherCollector(minsn_visitor_t):
    DISPATCHER_CLASS = adjustOllvmDispatcherInfo

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

    def reset(self):
        self.dispatcher_list = []
        self.explored_blk_serials = []

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list






class UnflattenerFakeJump(optblock_t):
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
        if blk.mba.maturity != hr.MMAT_CALLS:
            return 0
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        self.mba = blk.mba
        self.last_pass_nb_patch_done = 0

        # blk.optimize_block()
        self.retrieve_all_dispatchers()
        print("dispatcher_list = ",len(self.dispatcher_list))
        if len(self.dispatcher_list) == 0:
            print("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        self.last_pass_nb_patch_done = self.remove_flattening()

        # nb_clean = mba_deep_cleaning(self.mba, False)
        return 0


    def start(self):
        import pydevd_pycharm
        pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
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
        mmat = hr.MMAT_GLBOPT1
        if text is None and mmat is None:
            return (True, "Cancelled")

        if not sel and pfn:
            mbr = hr.mba_ranges_t(pfn)
        else:
            mbr = hr.mba_ranges_t()
            mbr.ranges.push_back(ida_range.range_t(sea, eea))

        hf = hr.hexrays_failure_t()
        ml = hr.mlist_t()
        self.mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)

        self.retrieve_all_dispatchers()
        print("dispatcher_list = ",len(self.dispatcher_list))
        if len(self.dispatcher_list) == 0:
            print("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        self.last_pass_nb_patch_done = self.remove_flattening()



    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def remove_flattening(self) -> int:
        for dispatcher_info in self.dispatcher_list:
            print("dispatcher_info:",hex(dispatcher_info.entry_block.blk.start))
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            nb_flattened_branches = 0
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
        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException("Dispatcher {0} predecessor {1} is not resolvable: {2}"
                                                   .format(dispatcher_info.entry_block.serial, dispatcher_father.serial,
                                                           mop_searched_values_list))

        # print(hex(mop_searched_values_list[0]))


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
