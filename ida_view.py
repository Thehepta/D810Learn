import ida_hexrays
import ida_idaapi
import idaapi
import ida_kernwin
import ida_funcs
import ida_ua
import ida_lines

ACTION_SHORTCUT = "Ctrl+Shift+G"
ACTION_NAME = "my:clearview"








class display_graph_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("activate")
        return 0

    def update(self, ctx):
        print("update")
        return ida_kernwin.AST_ENABLE_ALWAYS




class AsmView(ida_kernwin.simplecustviewer_t):
    def Create(self, title):
        if not super(AsmView, self).Create(title):
            return False
        self.SetContent()

        return True

    def SetContent(self):
        self.ClearLines()
        func = ida_funcs.get_func(idaapi.get_screen_ea())
        if func:
            ea = func.start_ea
            while ea < func.end_ea:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea):
                    line = f"{hex(ea)}: {ida_lines.generate_disasm_line(ea, 0)}"
                    self.AddLine(line)
                ea += insn.size
        else:
            self.AddLine("No function selected or function is invalid.")
        self.Refresh()


    def OnPopup(self, form, popup_handle):    # dynamic add popup
        action_clear = ida_kernwin.action_desc_t(None, 'Clear View', display_graph_ah_t())
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, action_clear, None)


def show_asm_view():

    view = AsmView()
    if view.Create("Assembly View"):
        view.Show()

# class my_plugin_t(ida_idaapi.plugin_t):
#     flags = ida_idaapi.PLUGIN_UNL
#     wanted_name = "ryruytyutyut"
#     wanted_hotkey = "Ctrl+Shift+G"
#     comment = "Sample plugin5 for Hex-Rays decompiler"
#     help = ""
#     def init(self):
#         if ida_hexrays.init_hexrays_plugin():
#             # show_asm_view()
#             return ida_idaapi.PLUGIN_KEEP # keep us in the memory
#     def term(self):
#         pass
#     def run(self, arg):
#         pass
#
# def PLUGIN_ENTRY():
#     return my_plugin_t()



if __name__ == '__main__':

    show_asm_view()