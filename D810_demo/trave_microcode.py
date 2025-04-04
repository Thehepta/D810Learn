import sys

import ida_kernwin as kw
import ida_funcs
import ida_ida
import ida_bytes
import ida_hexrays as hr
import ida_range

# -----------------------------------------------------------------------------
class printer_t(hr.vd_printer_t):
    """Converts microcode output to an array of strings."""
    def __init__(self, *args):
        hr.vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append(line)
        return 1
#
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
    mmat_name = None
    flags = 0
    if ok == 1:
        mmat_name, mmat = maturity_levels[form.mat_lvl.value]
    flags |= 0 if form.flags_short.checked else hr.MBA_SHORT
    form.Free()
    return (mmat_name, mmat, flags)


# -----------------------------------------------------------------------------
class microcode_viewer_t(kw.simplecustviewer_t):
    """Creates a widget that displays Hex-Rays microcode."""

    def __init__(self):
        super().__init__()
        self.insn_map = {}  # 用于存储行号到 minsn_t 对象的映射

    def Create(self, mba, title, mmat_name, fn_name,lines = []):
        self.title = "Microcode: %s" % title
        self.mba = mba
        self.mmat_name = mmat_name
        self.fn_name = fn_name
        if not kw.simplecustviewer_t.Create(self, self.title):
            return False
        self.lines = lines
        for line in lines:
            self.AddLine(line)
        return True

        # title = "Fun microcode FlowChart"
        # graph = MyGraph(title, self.mba)
        # if not graph.Show():
        #     print("Failed to display the graph")



def show_microcode():
    """Generates and displays microcode for an address range.
    An address range can be a selection of code or that of
    the current function."""
    sel, sea, eea = kw.read_range_selection(None)
    # get_screen_ea 获取光标的地址
    # get_func 通过这个地址，获取当前地址所在的函数
    pfn = ida_funcs.get_func(kw.get_screen_ea())
    if not sel and not pfn:
        return (False, "Position cursor within a function or select range")

    if not sel and pfn:
        # sea 函数起始地址  eea 函数结束地址
        sea = pfn.start_ea
        eea = pfn.end_ea

    addr_fmt = "%016x" if ida_ida.inf_is_64bit() else "%08x"
    # 获取函数名字
    fn_name = (ida_funcs.get_func_name(pfn.start_ea)
               if pfn else "0x%s-0x%s" % (addr_fmt % sea, addr_fmt % eea))

    F = ida_bytes.get_flags(sea)
    if not ida_bytes.is_code(F):
        return (False, "The selected range must start with an instruction")

    mmat_name, mmat, mba_flags = ask_desired_maturity()
    if mmat_name is None and mmat is None:
        return (True, "Cancelled")

    if not sel and pfn:
        mbr = hr.mba_ranges_t(pfn)
    else:
        mbr = hr.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(sea, eea))

    hf = hr.hexrays_failure_t()
    ml = hr.mlist_t()
    # 生产microcode
    mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)
    if not mba:
        return (False, "0x%s: %s" % (addr_fmt % hf.errea, hf.desc()))
    # mba 指令遍历回调接口
    vp = printer_t()
    mba.set_mba_flags(mba.get_mba_flags() | mba_flags)
    # 通过mba _print 进行指令遍历
    mba._print(vp)

    # ui类
    mcv = microcode_viewer_t()
    # vp.get_mc() 存储的是所有microcode的指令列表
    if not mcv.Create(mba, "%s (%s)" % (fn_name, mmat_name), mmat_name, fn_name,vp.get_mc()):
        return (False, "Error creating viewer")

    # 显示窗口
    mcv.Show()

    return (True,
            "Successfully generated microcode for 0x%s..0x%s" % (addr_fmt % sea, addr_fmt % eea))



if __name__ == '__main__':
    try:
        sys.setrecursionlimit(2000)
        show_microcode()
    except Exception as e:
        print(f"error: {e}")