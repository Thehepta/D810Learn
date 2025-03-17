from typing import List, Tuple, Union, Dict


# 定义 mblock_t 类表示块
class mblock_t:
    def __init__(self, serial: str):
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



# 目标函数：单个块查找是否有多个前驱的块，由代表同时存在于两个分支路径中
def get_block_with_multiple_predecessors(var_histories: List[MopHistory]) -> Tuple[Union[None, mblock_t],Union[None, Dict[int, List[MopHistory]]]]:
    # 第一个循环是进行MopHistory 循环，每个MopHistory 是一个分支
    for i, var_history in enumerate(var_histories):
        # 首先是循环所有分支，var_history.block_path[0] 是某个循环分支中的第一个块。从第一个块开始进入下层循环循环，下层循环会遍历当前分支的所有块
        pred_blk = var_history.block_path[0]
        # 从当前分支的第二个块开始循环，到最后，同时不断更新pred_blk，他永远是block的前一个块。也就是说这个横向双块循环
        for block in var_history.block_path[1:]:
            #前驱的serial作为下标后面进行存在判断
            tmp_dict = {pred_blk.serial: [var_history]}  # 在这里加入遍历
            # 循环上面MopHistory 的后一个
            # 进入下一层循环，这个循环是分支循环，i+1 表明，从最上面开始循环分支的下一个分支开始进行这个分支循环，也就是说，这里是横向双分支循环
            for j in range(i + 1, len(var_histories)):
                #var_histories[j].block_path 就是当前分支所有的块的列表，找一下这个块是否在这个列表
                blk_index = get_blk_index(block, var_histories[j].block_path)    #寻找 block 在  var_histories[j].block_path 中是否存在，如果存在返回下标
                if (blk_index - 1) >= 0:                                          # 如果存在，也就是这个上层分支的块在当前分支中找到了
                    other_pred = var_histories[j].block_path[blk_index - 1]       # 找到他的这个块的前驱
                    if other_pred.serial not in tmp_dict.keys():                  # 判断是否已经加入到列表中
                        tmp_dict[other_pred.serial] = []                          # 没有就创建，不存在加入到列表中，这个tmp_dict 存在列表，在上面创建的时候就会加入上层分支，这个块以及前驱到map里
                    tmp_dict[other_pred.serial].append(var_histories[j])

            if len(tmp_dict) > 1:                                                 # 这个tmp_dict 对应具体分支，具体块的前驱和块，因为是具体分支，虽然单个块有前驱，但是在对应具体分支的时候,一个块只会有一个前驱
                                                                                  # 所以如果出现两个，说明不同分支中同一个块有两个前驱，因为前驱是key,同一个前驱是不会有两个maps的
                return block, tmp_dict                                            # 返回这个块
            pred_blk = block
    return None, None


# -----------------测试代码------------------

# 定义一些测试块
A = mblock_t("A")
B = mblock_t("B")
C = mblock_t("C")
D = mblock_t("D")
E = mblock_t("E")
F = mblock_t("F")
G = mblock_t("G")
H = mblock_t("H")
I = mblock_t("I")
J = mblock_t("J")
K = mblock_t("K")
L = mblock_t("L")
M = mblock_t("M")
N = mblock_t("N")

# 定义每个变量的历史路径
var_histories = [
    MopHistory([A, B, C, D, J, K, L]), # 第一个变量经过块 A -> B -> C -> D
    MopHistory([E, H, C, F, M, N,L]),  # 第二个变量经过块 E -> H -> C -> F
    MopHistory([E, H, C, F, M, N,L]),  # 第二个变量经过块 E -> H -> C -> F
    MopHistory([E, H, C, F, M, N,L]),  # 第二个变量经过块 E -> H -> C -> F
]

# 调用函数并打印结果
block, predecessors = get_block_with_multiple_predecessors(var_histories)

print(f"Found block: {block}")
print(f"Predecessor mappings: {predecessors}")
