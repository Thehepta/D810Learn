from z3 import *
# 创建一个整数变量x
x = BitVec('x',32)
# 创建一个Z3求解器实例
solver = Solver()
# 定义表达式 (((x-1)*x) & 1) != 0
expr = ((((x - 1) * x) & 1) != 0)
# 将表达式添加到求解器
solver.add(expr)
# 检查是否存在满足表达式的x值
if solver.check() == sat:
    # 如果满足，打印满足条件的x值
    model = solver.model()
    print(f"满足条件的x值: {model[x]}")
else:
    # 如果不满足，打印无解
    print("没有满足条件的x值")