import sys

import ida_kernwin as kw
import ida_funcs
import ida_ida
import ida_bytes
import ida_hexrays as hr
import ida_range
import idaapi

# ----------------------------------------------------------------------------

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

            lines.append("{0}:{1}".format(blk_idx, hex(blk.head.ea)))
            insn = blk.head
            while insn:
                lines.append(insn.dstr())
                if insn == blk.tail:
                    break
                insn = insn.next
            label = "\n".join(lines)
            node_id = self.AddNode(label)
            nodes[blk_idx] = node_id

        for blk_idx in range(self._mba.qty):
            blk = self._mba.get_mblock(blk_idx)
            succset_list = [x for x in blk.succset]
            for succ in succset_list:
                blk_succ = self._mba.get_mblock(succ)
                if blk_succ.head == None:
                    continue
                if blk.head == None:
                    continue
                self.AddEdge(nodes[blk_idx], nodes[blk_succ.serial])
        return True

    def OnGetText(self, node_id):
        return self[node_id]


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

    title = "Fun microcode FlowChart"
    graph = MyGraph(title, mba)
    if not graph.Show():
        print("Failed to display the graph")

    return (True,
            "Successfully generated microcode for 0x%s..0x%s" % (addr_fmt % sea, addr_fmt % eea))



if __name__ == '__main__':
    try:
        sys.setrecursionlimit(2000)
        show_microcode()
    except Exception as e:
        print(f"error: {e}")