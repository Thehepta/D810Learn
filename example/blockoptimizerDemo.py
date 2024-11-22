import ida_hexrays
import idaapi


# 这个指令优化是作用域microcode层面的，也会多次调用，每个块都会调用
# func 函数不会调用一次，会调用很多次，每一个块都会调用一次
# ida 我们使用f5进行反编译的时候，成熟的一般在只能拦截到6左右
First = False

class UnflattenerOpt(ida_hexrays.optblock_t):

    def func(self, blk):
        global First

        if (blk.head != None):
            if blk.mba.maturity != ida_hexrays.MMAT_GLBOPT2:
                return 0
            if First:
                return 0
            if blk.serial == 2:
                print(blk.mba.maturity, hex(blk.head.ea))
                First = True
                self.codeFlow(blk.mba)

        return 0  # report the number of changes


    def codeFlow(self,mba):
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
        print(" show flocchart")
        title = "Fun microcode FlowChart"
        graph = MyGraph(title, mba)
        if not graph.Show():
            print("Failed to display the graph")


if __name__ == '__main__':  # 也可以直接在脚本里执行
    ida_hexrays.clear_cached_cfuncs()
    optimizer = UnflattenerOpt()
    optimizer.install()
