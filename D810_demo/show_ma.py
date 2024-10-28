import sys

import ida_kernwin as kw
import ida_funcs
import ida_ida
import ida_bytes
import ida_hexrays as hr
import ida_range
import ida_pro
import idaapi
from graphviz import Digraph

# -----------------------------------------------------------------------------

def ask_desired_maturity():
    """Displays a dialog which lets the user choose a maturity level
    of the microcode to generate."""
    maturity_levels = [
        ["MMAT_GENERATED", hr.MMAT_GENERATED],
        ["MMAT_PREOPTIMIZED", hr.MMAT_PREOPTIMIZED],
        ["MMAT_LOCOPT", hr.MMAT_LOCOPT],
        ["MMAT_CALLS", hr.MMAT_CALLS],
        ["MMAT_GLBOPT1", hr.MMAT_GLBOPT1],
        ["MMAT_GLBOPT2", hr.MMAT_GLBOPT2],
        ["MMAT_GLBOPT3", hr.MMAT_GLBOPT3],
        ["MMAT_LVARS", hr.MMAT_LVARS]]

    class MaturityForm(kw.Form):
        def __init__(self):
            self.title = "Display Microcode"
            form = ("STARTITEM {id:mat_lvl}\n"
                    "%s\n"
                    " \n"
                    "<Maturity level:{mat_lvl}>\n\n"
                    "<##Options##Output includes comments:{flags_short}>{chkgroup_flags}>\n\n" %
                    self.title)

            dropdown_ctl = kw.Form.DropdownListControl(
                [text for text, _ in maturity_levels])
            chk_ctl = kw.Form.ChkGroupControl(("flags_short",))

            controls = {"mat_lvl": dropdown_ctl,
                        "chkgroup_flags": chk_ctl}

            kw.Form.__init__(self, form, controls)

    form = MaturityForm()
    form, args = form.Compile()
    form.flags_short.checked = True
    ok = form.Execute()

    mmat = None
    text = None
    flags = 0
    if ok == 1:
        text, mmat = maturity_levels[form.mat_lvl.value]
    flags |= 0 if form.flags_short.checked else hr.MBA_SHORT
    form.Free()
    return (text, mmat, flags)


# -----------------------------------------------------------------------------
class microcode_viewer_t(kw.simplecustviewer_t):
    """Creates a widget that displays Hex-Rays microcode."""

    def __init__(self):
        super().__init__()
        self.insn_map = {}  # 用于存储行号到 minsn_t 对象的映射

    def Create(self, mba, title, mmat_name, fn_name):
        self.title = "Microcode: %s" % title
        self._mba = mba
        self.mmat_name = mmat_name
        self.fn_name = fn_name
        if not kw.simplecustviewer_t.Create(self, self.title):
            return False
        line_no = 0
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            insn = blk.head
            index = 0
            while insn:
                line = "{0}.{1}\t{2}    {3}".format(blk_idx, index, hex(insn.ea), insn.dstr())
                self.AddLine(line)
                self.insn_map[line_no] = insn
                index = index + 1
                line_no += 1
                if insn == blk.tail:
                    break
                insn = insn.next

        return True

    def OnKeydown(self, vkey, shift):   #响应键盘事件  快捷键
        if vkey == ord("X"):
            self.xref()
        if vkey == ord("D"):
            self.dominanceFlow()
        if vkey == ord("F"):
            self.codeFlow()
        if vkey == ord("G"):
            self.graphviz()

    def graphviz(self):
        dot = Digraph()
        for blk_idx in range(self._mba.qty):
            blk = self._mba.get_mblock(blk_idx)
            if blk.head == None:
                continue
            lines = []

            lines.append("{0}:{1}".format(blk_idx, hex(blk.head.ea)))
            insn = blk.head
            while insn:
                lines.append(insn.dstr())
                if insn == blk.tail:
                    break
                insn = insn.next
            label = "\n".join(lines)
            dot.node(str(blk_idx), label=label, shape="rect", style="filled", fillcolor="lightblue")

        for blk_idx in range(self._mba.qty):
            blk = self._mba.get_mblock(blk_idx)
            succset = [x for x in blk.succset]
            for succ in succset:
                blk_succ = self._mba.get_mblock(succ)
                if blk_succ.head is None:
                    continue
                if blk.head is None:
                    continue
                dot.edge(str(blk_idx), str(succ))

        dot.render("/home/chic/graph_with_content", format="png")
        print("图像已保存为 graph_with_content.png")

    def codeFlow(self):
        class MyGraph(idaapi.GraphViewer):
            def __init__(self, title, mba):
                idaapi.GraphViewer.__init__(self, title)
                self._mba = mba

            def OnRefresh(self):
                self.Clear()
                nodes = {}
                for blk_idx in range(self._mba.qty):
                    blk = self._mba.get_mblock(blk_idx)
                    if blk.head == None:
                        continue
                    lines = []

                    lines.append("{0}:{1}".format(blk_idx,hex(blk.head.ea)))
                    insn = blk.head
                    while insn:
                        lines.append(insn.dstr())
                        if insn == blk.tail:
                            break
                        insn = insn.next
                    label = "\n".join(lines)
                    node_id = self.AddNode(label)
                    nodes[blk.head.ea] = node_id

                for blk_idx in range(self._mba.qty):
                    blk = self._mba.get_mblock(blk_idx)
                    succset_list = [x for x in blk.succset]
                    for succ in succset_list:
                        blk_succ = self._mba.get_mblock(succ)
                        if blk_succ.head == None:
                            continue
                        if blk.head == None:
                            continue
                        if blk_succ.head.ea in nodes:
                            self.AddEdge(nodes[blk.head.ea], nodes[blk_succ.head.ea])
                return True

            def OnGetText(self, node_id):
                return self[node_id]



        title = "Fun microcode FlowChart"
        graph = MyGraph(title, self._mba)
        if not graph.Show():
            print("Failed to display the graph")

    def dominanceFlow(self):
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        pre_black = None
        pre_num = -1
        for blk_idx in range(self._mba.qty):
            blk = self._mba.get_mblock(blk_idx)
            # print(pre_num,len(blk.predset))
            if(pre_num < len(blk.predset)):
                pre_black = blk
                pre_num = len(blk.predset)
        print("Prefaceblock num:",hex(pre_black.serial))
        blk_preset_list = [x for x in pre_black.predset]
        print("Pred list:")
        print(blk_preset_list)

        def dfs( current_node, target_node, path, paths, visited):
            path.append(current_node.serial)
            visited.add(current_node.serial)

            for neighbor in current_node.succs():
                if neighbor.serial == target_node.serial and len(path) > 1:
                    paths.append(list(path))
                elif neighbor.serial not in visited:
                    dfs(neighbor, target_node, path, paths, visited)

            path.pop()
            visited.remove(current_node.serial)
        paths = []
        dfs(pre_black,pre_black,[],paths,set())
        print("branch list:")
        print(paths)
        cond_mod_t = pre_black.tail.l
        print("cond var:",cond_mod_t.dstr())
        cond_ml = hr.mlist_t()
        blk.append_use_list(cond_ml, cond_mod_t, hr.MUST_ACCESS)
        for path in paths:
            print(path)
            # for serial in path:
            #     blk = self._mba.get_mblock(serial)
            #     cur_ins = blk.head
            #     while cur_ins is not None:
            #         def_list = blk.build_def_list(cur_ins, hr.MAY_ACCESS | hr.FULL_XDSU)
                    # for defs in def_list:
                    # if cond_ml.has_common(def_list):
                        # print(path)
                        # print(cur_ins.dstr())
                    #     print(def_list.dstr())
                    #     break
                    # cur_ins = cur_ins.next


                # block_paht.append(blk)



                # use = blk.build_use_list(pre_black.tail, hr.MUST_ACCESS)
                # _def = blk.build_def_list(pre_black.tail, hr.MUST_ACCESS)

                # print(_def)
                # print(use)

    def xref(self):
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

        # print(self.GetLine(self.GetLineNo()))   #打印出这一行的字符串
        # print()               #打印行号
        selectCurrentWord = self.GetCurrentWord()
        ins_token = self.insn_map[self.GetLineNo()]
        if not ins_token:
            return False
        print(ins_token.dstr())         # 能够直接打印出这条指令的 microcode 的 字符串
        print(type(ins_token))         # 能够直接打印出这条指令的 microcode 的 字符串
        mop_r_str = ins_token.r.dstr()
        mop_l_str = ins_token.l.dstr()
        mop_d_str = ins_token.d.dstr()


        if selectCurrentWord.find(mop_l_str) != -1:
            print(mop_l_str)
            show_xrefs(self._mba,ins_token,ins_token.l)
        if selectCurrentWord.find(mop_d_str) != -1:
            print(mop_d_str)
            show_xrefs(self._mba,ins_token,ins_token.d)
        if selectCurrentWord.find(mop_r_str) != -1:
            print(mop_r_str)
            show_xrefs(self._mba,ins_token,ins_token.r)

        # print(mop_l_str,mop_r_str,mop_d_str)
        # print(selectCurrentWord)
        # self._mba



def collect_block_xrefs(out, mlist, blk, ins, find_uses):
    p = ins
    while p and not mlist.empty():
        use = blk.build_use_list(p, hr.MUST_ACCESS); # things used by the insn
        _def = blk.build_def_list(p, hr.MUST_ACCESS); # things defined by the insn
        plst = use if find_uses else _def
        if mlist.has_common(plst):
            if not p.ea in out:
                out.append(p.ea) # this microinstruction seems to use our operand
        mlist.sub(_def)
        p = p.next if find_uses else p.prev



def show_xrefs(mba,instr,mop):

    graph = mba.get_graph()
    ud = graph.get_ud(hr.GC_REGS_AND_STKVARS)
    du = graph.get_du(hr.GC_REGS_AND_STKVARS)

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        index = 0
        while insn:
            if insn == blk.tail:
                break
            insn = insn.next




    ctx = hr.op_parent_info_t()
    # start = ctx.topins.next
    mlist = hr.mlist_t()
    xrefs_out = ida_pro.eavec_t()
    collect_block_xrefs(xrefs_out, mlist, ctx.blk, instr.ea, False)

    serial = ctx.blk.serial # block number of the operand
    bc = du[serial]          # chains of that block
    voff = hr.voff_t(mop)
    ch = bc.get_chain(voff)   # chain of the operand
    if not ch:
        return # odd
    for bn in ch:
        b = ctx.mba.get_mblock(bn)
        ins = b.head
        tmp = hr.mlist_t()
        tmp.add(mlist)
        collect_block_xrefs(xrefs_out, tmp, b, ins, False)

    print(xrefs_out)
def show_microcode():
    """Generates and displays microcode for an address range.
    An address range can be a selection of code or that of
    the current function."""
    sel, sea, eea = kw.read_range_selection(None)
    pfn = ida_funcs.get_func(kw.get_screen_ea())
    if not sel and not pfn:
        return (False, "Position cursor within a function or select range")

    if not sel and pfn:
        sea = pfn.start_ea
        eea = pfn.end_ea

    addr_fmt = "%016x" if ida_ida.inf_is_64bit() else "%08x"
    fn_name = (ida_funcs.get_func_name(pfn.start_ea)
               if pfn else "0x%s-0x%s" % (addr_fmt % sea, addr_fmt % eea))

    F = ida_bytes.get_flags(sea)
    if not ida_bytes.is_code(F):
        return (False, "The selected range must start with an instruction")

    text, mmat, mba_flags = ask_desired_maturity()
    if text is None and mmat is None:
        return (True, "Cancelled")

    if not sel and pfn:
        mbr = hr.mba_ranges_t(pfn)
    else:
        mbr = hr.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(sea, eea))

    hf = hr.hexrays_failure_t()
    ml = hr.mlist_t()
    mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)
    if not mba:
        return (False, "0x%s: %s" % (addr_fmt % hf.errea, hf.desc()))

    mba.set_mba_flags(mba.get_mba_flags() | mba_flags)
    mcv = microcode_viewer_t()
    if not mcv.Create(mba, "%s (%s)" % (fn_name, text), text, fn_name):
        return (False, "Error creating viewer")

    mcv.Show()

    return (True,
            "Successfully generated microcode for 0x%s..0x%s" % (addr_fmt % sea, addr_fmt % eea))



if __name__ == '__main__':
    try:
        sys.setrecursionlimit(2000)
        show_microcode()
    except Exception as e:
        print(f"error: {e}")