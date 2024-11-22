from graphviz import Digraph

dot = Digraph(comment='Flowchart with Curved Edges')

# 设置图的属性
dot.attr(rankdir='LR', splines='true')  # 允许弯曲

# 添加节点
dot.node('A', 'Start', shape='ellipse', style='filled', fillcolor='lightblue')
dot.node('B', 'Process 1', shape='box', style='filled', fillcolor='lightgreen')
dot.node('C', 'Decision', shape='diamond', style='filled', fillcolor='lightcoral')
dot.node('D', 'Process 2', shape='box', style='filled', fillcolor='lightgreen')
dot.node('E', 'End', shape='ellipse', style='filled', fillcolor='lightblue')

# 添加边
dot.edge('A', 'B', label='Step 1')
dot.edge('B', 'C', label='Step 2')
dot.edge('C', 'D', label='Yes', color='green')
dot.edge('C', 'E', label='No', color='red')
dot.edge('D', 'E', label='Step 3')

# 保存图像
dot.render('/home/chic/curved_flowchart')

print("曲线流程图已生成并保存")
