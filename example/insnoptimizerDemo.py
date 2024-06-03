import ida_hexrays
import ida_idaapi

# 这个指令优化是作用域microcode层面的，会根据不同的成熟度，各调用你一次，同时每个成熟度生成的每一条指令一会调用一次，每一条指令跟生成的miocrocode 是对应的

class sample_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk, ins, optflags):
        print(blk.mba.maturity,hex(ins.ea))
        return 0                  # report the number of changes


if __name__ == '__main__':
    ida_hexrays.clear_cached_cfuncs()
    optimizer = sample_optimizer_t()
    optimizer.install()
    # optimizer.remove()



