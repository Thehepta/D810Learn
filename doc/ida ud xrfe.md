example: xrfe.py
使用方法，在ida汇编视图中选择一个需要查找引用的寄存器，然后执行这个脚本，会出现一个界面显示一个引用界面


### 思路说明
这个查找引用的方式，不是通过汇编语言直接查找的，而是通过先生成microcode，然后然后使用microcode的api,先把要查找的指令的操作数转变成microcode 的mop，然后再用microcode 的指令分析api查找，找到对应的microcode minsn。然后返回minsn对应的指令的地址。
其实即使通过microcode查找，然后返回对应的地址。
查找使用和查找定义其实是分开查找的。
这个demo 

### 代码详细分析
```
import ida_pro
import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_lines

def collect_block_xrefs(out, mlist, blk, ins, find_uses):
    p = ins
    while p and not mlist.empty():                          # 遍历所有指令
        use = blk.build_use_list(p, ida_hexrays.MUST_ACCESS); # things used by the insn    构建blk 中的某条指令使用信息，使用类型为ida_hexrays.MUST_ACCESS
        _def = blk.build_def_list(p, ida_hexrays.MUST_ACCESS); # things defined by the insn  构建blk 中的某条指令定义信息，定义类型为ida_hexrays.MUST_ACCESS
        plst = use if find_uses else _def                 # 判断这个是查找使用还是查找定义
        if mlist.has_common(plst):                        # mlist中保存的要查找的mop，以plist 中的进行对比
            if not p.ea in out:
                out.append(p.ea) # this microinstruction seems to use our operand   如果没有保存过，就保存进去，已经保存的不保存了
        mlist.sub(_def)
        p = p.next if find_uses else p.prev       #根据使用还是定义，方向不同


def collect_xrefs(out, ctx, mop, mlist, du, find_uses):
    # first collect the references in the current block
    start = ctx.topins.next if find_uses else ctx.topins.prev;      #如果查找使用的向后查找，如果查找定义，向前查找，配合后面代码一起理解
    collect_block_xrefs(out, mlist, ctx.blk, start, find_uses)

    # then find references in other blocks
    serial = ctx.blk.serial; # block number of the operand
    bc = du[serial]          # chains of that block         du是一个chains，是一个list，通过serial 可以获取对应serial 的块的定义信息
    voff = ida_hexrays.voff_t(mop)                         # 通过mop获取一个偏移
    ch = bc.get_chain(voff)   # chain of the operand      # 通过偏移在bc 中查找所有定义块的列表
    if not ch:
        return # odd
    for bn in ch:                                         # 遍历所有的定义块的列表
        b = ctx.mba.get_mblock(bn)
        ins = b.head if find_uses else b.tail
        tmp = ida_hexrays.mlist_t()
        tmp.add(mlist)
        collect_block_xrefs(out, tmp, b, ins, find_uses)  # 某一个块的具体使用或者定义分析


class xref_chooser_t(ida_kernwin.Choose):
    def __init__(self, xrefs, t, n, ea, gco):
        ida_kernwin.Choose.__init__(
            self,
            t,
            [["Type", 3], ["Address", 16], ["Instruction", 60]])

        self.xrefs = xrefs
        self.ndefs = n
        self.curr_ea = ea
        self.gco = gco
        self.items = [ self._make_item(idx) for idx in range(len(xrefs)) ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def _make_item(self, idx):
        ea = self.xrefs[idx]
        both_mask = ida_hexrays.GCO_USE|ida_hexrays.GCO_DEF
        both = (self.gco.flags & both_mask) == both_mask
        if ea == self.curr_ea and both:
            type_str = "use/def"
        elif idx < self.ndefs:
            type_str = "def"
        else:
            type_str = "use"
        insn = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        return [type_str, "%08x" % ea, insn]


def show_xrefs(ea, gco, xrefs, ndefs):
    title = "xrefs to %s at %08x" % (gco.name, ea)
    xc = xref_chooser_t(xrefs, title, ndefs, ea, gco)
    i = xc.Show(True)
    if i >= 0:
        ida_kernwin.jumpto(xrefs[i])


import pydevd_pycharm
pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
if ida_hexrays.init_hexrays_plugin():
    ea = ida_kernwin.get_screen_ea()
    pfn = ida_funcs.get_func(ea)
    w = ida_kernwin.warning
    if pfn:
        F = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(F):
            gco = ida_hexrays.gco_info_t()            # 获取当之前光标处的操作数(operand)
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
                        ncalls = mba.analyze_calls(ida_hexrays.ACFL_GUESS)
                        if ncalls < 0:
                            print("%08x: failed to determine some calling conventions", pfn.start_ea)
                        mlist = ida_hexrays.mlist_t()
                        if gco.append_to_list(mlist, mba):
                            ctx = ida_hexrays.op_parent_info_t()     # 这个ctx 当作参数传进去，用来获取ea 这个地址 的上下文信息，例如当前mba,blk,topins,和curins
                            mop = mba.find_mop(ctx, ea, gco.is_def(), mlist)   # 在当前mba 这个微码中，通过地址查找mop，这个mop需要很mlist 中的匹配
                            if mop:
                                xrefs = ida_pro.eavec_t()
                                ndefs = 0
                                graph = mba.get_graph()
                                ud = graph.get_ud(ida_hexrays.GC_REGS_AND_STKVARS)    # mba中所有的使用信息
                                du = graph.get_du(ida_hexrays.GC_REGS_AND_STKVARS)    # mba中所有的定义信息
                                if gco.is_use():                                      # 定义和使用的查找方法是一样的，但是api有一定的差别，所以最好一个参数有点区别
                                    collect_xrefs(xrefs, ctx, mop, mlist, ud, False)
                                    ndefs = xrefs.size()
                                    if ea not in xrefs:
                                        xrefs.append(ea)
                                if gco.is_def():
                                    if ea not in xrefs:
                                        xrefs.append(ea)
                                        ndefs = len(xrefs)
                                    collect_xrefs(xrefs, ctx, mop, mlist, du, True)
                                show_xrefs(ea, gco, xrefs, ndefs)
                            else:
                                w("Could not find the operand in the microcode, sorry")
                        else:
                            w("Failed to represent %s as microcode list" % gco.name)
                    else:
                        w("%08x: %s" % (errea, ida_hexrays.get_merror_desc(merr, mba)))
                else:
                    w("%08x: %s" % (hf.errea, hf.str))
            else:
                w("Could not find a register or stkvar in the current operand")
        else:
            w("Please position the cursor on an instruction")
    else:
        w("Please position the cursor within a function")
else:
    print('vds12: Hex-rays is not available.')
```