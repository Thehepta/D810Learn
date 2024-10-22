import ida_hexrays
import idaapi


# 这个代码主要进行测试 func 函数返回的数据为为非零
# 经过测试发现 如果func函数返回为非零会再次调用这个函数，直到这个函数为零，才会正常返回，如果一直不返回为0，会一直调用直到卡死
# 再次调用，这个时候要分析的数据应该是已经处于我们上次修改过后的结果了
# 返回 1 和 2，调用测试好像一样，不知道不同数值调用有什么区别

# 经过测试 MMAT_GLBOPT2 原始调用次数为2，返回1后，发现调用次数为4次了
First = True

class UnflattenerOpt(ida_hexrays.optblock_t):

    def func(self, blk):
        global First
        print("maturity:",blk.mba.maturity,"serial:",blk.serial)
        if (blk.head != None):
            if blk.mba.maturity != ida_hexrays.MMAT_GLBOPT2:
                return 0

            if blk.serial == 2:
                print("entry blk.serial == 2")
                First = False
                # self.codeFlow(blk.mba)
            if First:
                print("retuen 1")
                return 1
        return 0  # report the number of changes





if __name__ == '__main__':  # 也可以直接在脚本里执行
    ida_hexrays.clear_cached_cfuncs()
    optimizer = UnflattenerOpt()
    optimizer.install()
