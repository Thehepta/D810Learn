from graphviz import Digraph
import os


os.environ['PATH'] = os.pathsep + r'C:\Program Files\Graphviz\bin'


# 创建有向图
dot = Digraph()

# 添加节点并设置标签内容
dot.node("A", label="Node A\nContent: Start", shape="rect", style="filled", fillcolor="lightblue")
dot.node("B", label="Node B\nContent: Middle", shape="rect", style="filled", fillcolor="lightblue")
dot.node("C", label="Node C\nContent: End", shape="rect", style="filled", fillcolor="lightblue")

# 添加边
dot.edge("A", "B")
dot.edge("B", "C")

# 保存图像
dot.render("graph_with_content", format="png")

print("图像已保存为 graph_with_content.png")