#  a1[2] + *a1 - 2005823921 + 2005823944 - (-(~a1[2] + a1[1] - *a1 + 12) - 17 - a1[1]);

from z3 import *

# 定义变量
a1_2 = BitVec('a1_2', 32)
a1_1 = BitVec('a1_1', 32)
a1_0 = BitVec('a1_0', 32)  # *a1

# 定义复杂表达式
part1 = a1_2 + a1_0 - 2005823921 + 2005823944
part2 = -(~a1_2 + a1_1 - a1_0 + 12) - 17 - a1_1
expr = part1 - part2

# 创建求解器
solver = Solver()

# 简化表达式
result = simplify(expr)

print(result)