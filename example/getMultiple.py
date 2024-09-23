from typing import List, Tuple, Union, Dict


# 定义 mblock_t 类表示块
class mblock_t:
    def __init__(self, serial: int):
        self.serial = serial

    def __repr__(self):
        return f"Block({self.serial})"


# 定义 MopHistory 类表示变量的历史路径
class MopHistory:
    def __init__(self, block_path: List[mblock_t]):
        self.block_path = block_path

    def __repr__(self):
        return f"MopHistory({[block.serial for block in self.block_path]})"


# 假设的 get_blk_index 函数，找到块在路径中的位置
def get_blk_index(block: mblock_t, block_path: List[mblock_t]) -> int:
    try:
        return block_path.index(block)
    except ValueError:
        return -1


#d810通过某个终止块和分发器来寻找出他们之间的MopHistory，就是分支如果有多个分支，说明有多个值，这种时候需要进行优化，将终止块复制，将分支拆开。


# 目标函数：查找有多个前驱的块
def get_block_with_multiple_predecessors(var_histories: List[MopHistory]) -> Tuple[Union[None, mblock_t],Union[None, Dict[int, List[MopHistory]]]]:
    # 第一个循环是进行MopHistory 循环，每个MopHistory 是一个分支
    for i, var_history in enumerate(var_histories):
        # 循环MopHistory其中某个的 第一个 块开始作为前驱 ，后面会不断更新
        pred_blk = var_history.block_path[0]
        # 循环MopHistory其中某个的 第2块开始循环到最后一个
        for block in var_history.block_path[1:]:
            #前驱作为下标后面进行存在判断
            tmp_dict = {pred_blk.serial: [var_history]}  # 在这里加入遍历
            # 循环上面MopHistory 的后一个
            for j in range(i + 1, len(var_histories)):
                #找到前面的MopHistory 循环的块，是否在路径中
                blk_index = get_blk_index(block, var_histories[j].block_path)    #寻找 block 在  var_histories[j].block_path 中是否存在，如果存在返回下标

                if (blk_index - 1) >= 0:                                          # 如果存在
                    other_pred = var_histories[j].block_path[blk_index - 1]       # 找到他的这个块的前驱
                    if other_pred.serial not in tmp_dict.keys():                  # 判断是否已经加入到列表中
                        tmp_dict[other_pred.serial] = []                          # 没有就创建，不存在加入到列表中
                    tmp_dict[other_pred.serial].append(var_histories[j])
            if len(tmp_dict) > 1:
                return block, tmp_dict                                              #返回这个块
            pred_blk = block
    return None, None


# -----------------测试代码------------------

# 定义一些测试块
A = mblock_t(1)
B = mblock_t(2)
C = mblock_t(3)
D = mblock_t(4)
E = mblock_t(5)
F = mblock_t(6)
G = mblock_t(7)
H = mblock_t(8)
I = mblock_t(9)

# 定义每个变量的历史路径
var_histories = [
    MopHistory([A, B, C, D]),  # 第一个变量经过块 A -> B -> C -> D
    MopHistory([E, H, C, F]),  # 第二个变量经过块 E -> H -> C -> F
]

# 调用函数并打印结果
block, predecessors = get_block_with_multiple_predecessors(var_histories)

print(f"Found block: {block}")
print(f"Predecessor mappings: {predecessors}")
