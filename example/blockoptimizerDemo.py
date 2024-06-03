import ida_hexrays

# 这个指令优化是作用域microcode层面的，也会多次调用，每个块都会调用
class UnflattenerOpt(ida_hexrays.optblock_t):

    def func(self, blk):
        if(blk.head != None):
            print(blk.mba.maturity,hex(blk.head.ea))

        return 0             # report the number of changes




if __name__ == '__main__':      #也可以直接在脚本里执行
    ida_hexrays.clear_cached_cfuncs()
    optimizer = UnflattenerOpt()
    optimizer.install()

