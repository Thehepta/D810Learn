from typing import List

import ida_hexrays
from d810.hexrays_formatters import format_mop_list
from d810.optimizers.flow.flattening.generic import GenericDispatcherBlockInfo
from d810.optimizers.flow.flattening.unflattener import OllvmDispatcherCollector
from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, get_all_possibles_values
from d810.tracker import MopHistory, MopTracker
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t


class UnflattenerFakeJump(optblock_t):
    DISPATCHER_COLLECTOR_CLASS = OllvmDispatcherCollector
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
        if blk.mba.maturity != ida_hexrays.MMAT_CALLS:
            return 0
        import pydevd_pycharm
        pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        self.mba = blk.mba
        self.last_pass_nb_patch_done = 0

        # blk.optimize_block()
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            print("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        self.last_pass_nb_patch_done = self.remove_flattening()

        # nb_clean = mba_deep_cleaning(self.mba, False)
        return 0


    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def remove_flattening(self) -> int:
        for dispatcher_info in self.dispatcher_list:
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            nb_flattened_branches = 0
            for dispatcher_father in dispatcher_father_list:
                try:
                    nb_flattened_branches += self.resolve_dispatcher_father(dispatcher_father, dispatcher_info)
                except NotResolvableFatherException as e:
                    print("NotResolvableFatherException")

    def resolve_dispatcher_father(self, dispatcher_father, dispatcher_info):
        dispatcher_father_histories = self.get_dispatcher_father_histories(dispatcher_father,
                                                                           dispatcher_info.entry_block)
        father_is_resolvable = self.check_if_histories_are_resolved(dispatcher_father_histories)
        if not father_is_resolvable:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))
        mop_searched_values_list = get_all_possibles_values(dispatcher_father_histories,
                                                            dispatcher_info.entry_block.use_before_def_list,
                                                            verbose=False)
        print(mop_searched_values_list)


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
    optimizer = UnflattenerFakeJump()
    optimizer.install()