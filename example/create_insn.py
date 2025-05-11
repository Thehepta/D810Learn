
import ida_hexrays


# ida mop 的寄存器,是通过mop传入数据来分辨是什么数据,但是并没有,并没有说明如何设置为某个具体寄存器
# 经过测试发现 是通过传入的整数的bit来区分是什么寄存器,前4个bit 16中选择对应mop的类型,4各以后的bit开始对应寄存器,后面一个整数是长度,size
def create_insn():
    insn = ida_hexrays.minsn_t(0)
    print(insn.dstr())
    insn.opcode = ida_hexrays.m_add  # 加法操作
    insn.l = ida_hexrays.mop_t(ida_hexrays.mop_r, 8)  # 左操作数
    insn.r = ida_hexrays.mop_t(64, 8)  # 右操作数
    insn.d = ida_hexrays.mop_t(32, 8)  # 右操作数
    print(insn.dstr())


def create_reg():
    mop_reg = ida_hexrays.mop_t()
    mop_reg.make_reg(0)
    print("0:",mop_reg.dstr())
    mop_reg.make_reg(8)
    print("8:",mop_reg.dstr())
    mop_reg.make_reg(16)
    print("16:",mop_reg.dstr())
    mop_reg.make_reg(32)
    print("32:",mop_reg.dstr())
    mop_reg.make_reg(64)
    print("64:",mop_reg.dstr())
    mop_reg.make_reg(128)
    print("128:",mop_reg.dstr())
    mop_reg.make_reg(256)
    print("256:",mop_reg.dstr())
    print("mop_reg is mop_r:", mop_reg.t)
    print("mop_reg is mop_r:", ida_hexrays.mop_r)

    # if mop_reg.oprops == ida_hexrays.mop_r:
    #     print("mop_reg is mop_r:",mop_reg.oprops)


def create_num():
    mop_num = ida_hexrays.mop_t()
    mop_num.make_number(100, 8)
    print(mop_num.dstr())
    print("mop_num is mop_r:", mop_num.t)
    print("mop_reg is mop_r:", ida_hexrays.mop_n)


if __name__ == '__main__':
    try:
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
        create_insn()
        create_num()
        create_reg()
    except Exception as e:
        print(f"error: {e}")