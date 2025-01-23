```
mop_z = cvar.mop_z
r"""
none
"""
mop_r = cvar.mop_r
r"""
register (they exist until MMAT_LVARS)
"""
mop_n = cvar.mop_n
r"""
immediate number constant
"""
mop_str = cvar.mop_str
r"""
immediate string constant (user representation)
"""
mop_d = cvar.mop_d
r"""
result of another instruction
"""
mop_S = cvar.mop_S
r"""
local stack variable (they exist until MMAT_LVARS)
"""
mop_v = cvar.mop_v
r"""
global variable
"""
mop_b = cvar.mop_b
r"""
micro basic block (mblock_t)
"""
mop_f = cvar.mop_f
r"""
list of arguments
"""
mop_l = cvar.mop_l
r"""
local variable
"""
mop_a = cvar.mop_a
r"""
mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
"""
mop_h = cvar.mop_h
r"""
helper function
"""
mop_c = cvar.mop_c
r"""
mcases
"""
mop_fn = cvar.mop_fn
r"""
floating point constant
"""
mop_p = cvar.mop_p
r"""
operand pair
"""
mop_sc = cvar.mop_sc
r"""
scattered
"""
NOSIZE = cvar.NOSIZE
r"""
wrong or unexisting operand size
"""
```