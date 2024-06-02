from ida_hexrays import mblock_t, mop_t

from d810.tracker import MopTracker
from utils import get_all_possibles_values


class UnflattenerFakeJump():

    def analyze_blk(self, blk: mblock_t) -> int:

        op_compared = mop_t(blk.tail.l)
        blk_preset_list = [x for x in blk.predset]
        nb_change = 0
        for pred_serial in blk_preset_list:
            cmp_variable_tracker = MopTracker([op_compared], max_nb_block=100, max_path=1000)
            cmp_variable_tracker.reset()
            pred_blk = blk.mba.get_mblock(pred_serial)
            pred_histories = cmp_variable_tracker.search_backward(pred_blk, pred_blk.tail)

            father_is_resolvable = all([father_history.is_resolved() for father_history in pred_histories])
            if not father_is_resolvable:
                return 0
            pred_values = get_all_possibles_values(pred_histories, [op_compared])
            pred_values = [x[0] for x in pred_values]
            if None in pred_values:
                print("Some path are not resolved, can't fix jump")
                return 0
            print("Pred {0} has {1} possible path ({2} different cst): {3}"
                               .format(pred_blk.serial, len(pred_values), len(set(pred_values)), pred_values))
            if self.fix_successor(blk, pred_blk, pred_values):
                nb_change += 1
        return nb_change
