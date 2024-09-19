import ida_hexrays
import ida_funcs
import ida_kernwin


def collect_block_xrefs( mlist, blk, ins,find_uses):
    p = ins
    while p and not mlist.empty():
        use = blk.build_use_list(p, ida_hexrays.MUST_ACCESS); # things used by the insn
        _def = blk.build_def_list(p, ida_hexrays.MUST_ACCESS); # things defined by the insn
        plst = use if find_uses else _def
        if mlist.has_common(plst):
            print("collect_block_xrefs:",hex(p.ea))
        p = p.next if find_uses else p.prev

def  collect_use_xrefs( ctx, mop, mlist, du):
    start = ctx.topins.next
    serial = ctx.blk.serial;  # block number of the operand
    collect_block_xrefs(mlist, ctx.blk, start,False)

    bc = du[serial]
    voff = ida_hexrays.voff_t(mop)
    ch = bc.get_chain(voff)  # chain of the operand
    if not ch:
        return # odd
    for bn in ch:
        b = ctx.mba.get_mblock(bn)
def show_operand_info():
    if ida_hexrays.init_hexrays_plugin():
        ea = ida_kernwin.get_screen_ea()
        pfn = ida_funcs.get_func(ea)
        w = ida_kernwin.warning
        if pfn:
            gco = ida_hexrays.gco_info_t()
            if ida_hexrays.get_current_operand(gco):
                    # generate microcode
                hf = ida_hexrays.hexrays_failure_t()
                mbr = ida_hexrays.mba_ranges_t(pfn)
                mba = ida_hexrays.gen_microcode(
                        mbr,
                        hf,
                        None,
                        ida_hexrays.DECOMP_WARNINGS | ida_hexrays.DECOMP_NO_CACHE,
                        ida_hexrays.MMAT_PREOPTIMIZED)
                if mba:
                    merr = mba.build_graph()
                    if merr == ida_hexrays.MERR_OK:
                        mlist = ida_hexrays.mlist_t()
                        if gco.append_to_list(mlist, mba):
                            ctx = ida_hexrays.op_parent_info_t()
                            mop = mba.find_mop(ctx, ea, gco.is_def(), mlist)
                            if mop:
                                print("found mop:",mop.dstr())
                                graph = mba.get_graph()
                                ud = graph.get_ud(ida_hexrays.GC_REGS_AND_STKVARS)
                                du = graph.get_du(ida_hexrays.GC_REGS_AND_STKVARS)
                                if gco.is_use():
                                    collect_use_xrefs(ctx, mop, mlist, ud)
    # 获取当前指令的微代码
    # insn = None
    # for i in range(1,mba.qty):
    #     block = mba.get_mblock(i)
    #     ins = block.head
    #
    #     while ins:
    #         if ins.ea == ea:
    #             insn = ins
    #             break
    #         ins = ins.next
    #     if insn:
    #         break
    #
    # if not insn:
    #     print("Failed to get microcode for the instruction at 0x%x" % ea)
    #     return
    #
    # # 获取操作数列表
    # mlist = ida_hexrays.mlist_t()
    #
    # if insn.t == ida_hexrays.mop_l:
    #     mlist.add(insn.l)
    # elif insn.t == ida_hexrays.mop_d:
    #     mlist.add(insn.d)
    # elif insn.t == ida_hexrays.mop_v:
    #     mlist.add(insn.v)
    #
    #
    # # 遍历操作数列表并显示信息
    # print("Operand list for instruction at 0x%x:" % ea)
    # for i in range(len(mlist)):
    #     operand = mlist[i]
    #     print("Operand %d:" % i)
    #     print("  Type: %d" % operand.opcode)
    #     print("  Size: %d" % operand.size)
    #     print("  Value: %s" % operand.print1(None))


# Example usage:
import pydevd_pycharm
pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
try:
    show_operand_info()
except Exception as e:
    print(e);
