
#ida 中的python插件可以相互引用,这个是一个引用genmy插件的demo, 从下面导入genmy中的函数
from datetime import datetime

from genmy import *

import os, shutil, errno, re

import ida_idaapi
import ida_bytes
import ida_range
import ida_kernwin as kw
import ida_hexrays as hr
import ida_funcs
import ida_diskio
import ida_ida
import ida_graph
import ida_lines
import ida_moves


def getMba():
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

    F = ida_bytes.get_flags(sea)
    if not ida_bytes.is_code(F):
        return (False, "The selected range must start with an instruction")

    text, mmat, mba_flags = ask_desired_maturity()  # dialog
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

    # show_microcode_graph(mba ,"text_graph")

    now = datetime.now()
    graphviz(mba, "/home/chic/unfla/" + now.strftime("%H-%M-%S-%f"))

getMba()