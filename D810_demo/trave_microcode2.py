import sys

import ida_kernwin as kw
import ida_funcs
import ida_ida
import ida_bytes
import ida_hexrays as hr
import ida_range

# ----------------------------------------------------------------------------

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
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        self.title = "Microcode: %s" % title
        self.mba = mba
        self.mmat_name = mmat_name
        self.fn_name = fn_name
        nodes = {}
        if not kw.simplecustviewer_t.Create(self, self.title):
            return False
        for blk_idx in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_idx)
            if blk.head == None:
                continue
            insn = blk.head
            while insn:
                self.AddLine(insn.dstr())
                if insn == blk.tail:
                    break
                insn = insn.next

        return True

        # self.lines = lines
        # for line in lines:
        #     self.AddLine(line)
        # return True

        # title = "Fun microcode FlowChart"
        # graph = MyGraph(title, self.mba)
        # if not graph.Show():
        #     print("Failed to display the graph")



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