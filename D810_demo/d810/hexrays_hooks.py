import logging

from ida_hexrays import *
from d810.hexrays_helpers import check_ins_mop_size_are_ok, append_mop_if_not_in_list
from d810.hexrays_formatters import format_minsn_t, format_mop_t, maturity_to_string, mop_type_to_string, \
    dump_microcode_for_debug

helper_logger = logging.getLogger('D810.helper')


class InstructionDefUseCollector(mop_visitor_t):
    def __init__(self):
        super().__init__()
        self.unresolved_ins_mops = []
        self.memory_unresolved_ins_mops = []
        self.target_mops = []

    def visit_mop(self, op: mop_t, op_type: int, is_target: bool):
        if is_target:
            append_mop_if_not_in_list(op, self.target_mops)
        else:
            # TODO whatever the case, in the end we will always return 0. May be this code can be better optimized.
            # TODO handle other special case (e.g. ldx ins, ...)
            if op.t == mop_S:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == mop_r:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == mop_v:
                append_mop_if_not_in_list(op, self.memory_unresolved_ins_mops)
            elif op.t == mop_a:
                if op.a.t == mop_v:
                    return 0
                elif op.a.t == mop_S:
                    return 0
                helper_logger.warning("Calling visit_mop with unsupported mop type {0} - {1}: '{2}'"
                                      .format(mop_type_to_string(op.t), mop_type_to_string(op.a.t), format_mop_t(op)))
                return 0
            elif op.t == mop_n:
                return 0
            elif op.t == mop_d:
                return 0
            elif op.t == mop_h:
                return 0
            elif op.t == mop_b:
                return 0
            else:
                helper_logger.warning("Calling visit_mop with unsupported mop type {0}: '{1}'"
                                      .format(mop_type_to_string(op.t), format_mop_t(op)))
        return 0

