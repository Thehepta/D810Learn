import ida_hexrays
import ida_idaapi
from d810.ast import minsn_to_ast, AstNode, AstLeaf, AstConstant


# 这个指令优化是作用域microcode层面的，会根据不同的成熟度，各调用你一次，同时每个成熟度生成的每一条指令一会调用一次，每一条指令跟生成的miocrocode 是对应的


def signature_generator(ref_sig):
    for i, x in enumerate(ref_sig):
        if x not in ["N", "L"]:
            for sig_suffix in signature_generator(ref_sig[i + 1:]):
                yield ref_sig[:i] + ["L"] + sig_suffix
    yield ref_sig


class sample_optimizer_t(ida_hexrays.optinsn_t):

    def __init__(self):
        super().__init__()
        self.instruction_visitor = InstructionVisitorManager(self)
        self.PredOdd1 = AstNode(ida_hexrays.m_and,
                                AstNode(ida_hexrays.m_mul,

                                        AstNode(ida_hexrays.m_sub,
                                                AstLeaf('x_0'),
                                                AstConstant('1', 1)),
                                        AstLeaf('x_0')),
                                AstConstant('1', 1))
        self.replace = AstNode(ida_hexrays.m_mov, AstConstant("val_0"))

    def func(self, blk, ins) -> bool:

        if (blk.head != None):
            if blk.mba.maturity != ida_hexrays.MMAT_LOCOPT:
                return False
        # print("mmat:",blk.mba.maturity)
        try:
            #     print("start for_all_insns")
            optimization_performed = self.optimize(blk, ins)
            ins.for_all_insns(self.instruction_visitor)
            # if optimization_performed:
            #     ins.optimize_solo()

        except RuntimeError as e:
            print("RuntimeError while optimizing ins")
        return False  # report the number of changes

    def optimize(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:

        try:
            if ins.opcode == ida_hexrays.m_and:
                # print("visit:{0}".format(ins.dstr()))
                tmp = minsn_to_ast(ins)
                new_ins = self.check_pattern_and_replace(self.PredOdd1, tmp)
                if new_ins is not None:
                    ins.swap(new_ins)
                # print(new_ins.dstr())
        except Exception as e:
            pass
            # print(e)

        return False

    def check_pattern_and_replace(self, candidate_pattern: AstNode, test_ast: AstNode):
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        new_instruction = ida_hexrays.minsn_t(test_ast.ea)
        mop_num = ida_hexrays.mop_t()
        mop_num.make_number(0, 8)
        new_instruction.opcode = ida_hexrays.m_mov
        new_instruction.l = mop_num
        # mop_reg = ida_hexrays.mop_t()
        # mop_reg.make_reg(16)
        new_instruction.d = test_ast.dst.mop
        # is_ok = self.replace.update_leafs_mop(candidate_pattern)
        # if not is_ok:
        #     return None
        # new_instruction = ida_hexrays.minsn_t(test_ast.ea)
        # new_instruction.opcode = ida_hexrays.m_mov
        # new_instruction.l = ida_hexrays.mop_t(test_ast.d, 8)  # 左操作数
        # new_instruction = self.get_replacement(candidate_pattern)
        # # print("fix:",new_ins)
        # return new_instruction
        return new_instruction

    def get_replacement(self, candidate: AstNode):

        new_ins = self.replace.create_minsn(candidate.ea, candidate.dst_mop)
        return new_ins


class InstructionVisitorManager(ida_hexrays.minsn_visitor_t):

    def __init__(self, optimizer: sample_optimizer_t):
        super().__init__()
        self.instruction_optimizer = optimizer

    def visit_minsn(self) -> bool:
        return self.instruction_optimizer.optimize(self.blk, self.curins)
        # return  False  #这个函数需要返回false ,否则可能只执行一次,无法进行指令遍历


if __name__ == '__main__':
    ida_hexrays.clear_cached_cfuncs()
    optimizer = sample_optimizer_t()
    optimizer.install()
    # optimizer.remove()
