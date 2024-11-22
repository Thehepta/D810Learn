
import networkx as netx
import matplotlib.pyplot as plt
import urllib


def py_graph():
    g = netx.Graph()  # 创建空图
    g.add_edge('a', 'b')  # 插入一条连接a,b的边到图中，节点将自动插入
    g.add_edge('b', 'c')  # 再插入一条连接b，c的边
    g.add_edge('c', 'a')  # 再插入一条连接c,a的边
    netx.draw(g)  # 输出一个三角形的图
    plt.show()  # ui显示图形
    #plt.savefig('./generated_image.png') 如果你想保存图片，去除这句的注释
    print(g.nodes())  # 输出图g的节点值
    print(g.edges(data=True))  # 输出图g的边值
    g.remove_edge('c', 'a') #移除一条连接c,a的边
    print(g.edges())  # 输出图g的边值
    g.remove_node("a")
    print(g.nodes())  # 输出图g的节点值
    print(g.edges())  # 输出图g的边值



def py_DiGraph():
    G = netx.DiGraph()
    netx.add_path(G, [0, 1, 2, 3])
    print(G.in_degree(0))  # node 0 with degree 0
    print(G.nodes())  # 输出图g的节点值
    print(G.edges())  # 输出图g的边值
    G.add_edge(1,3)
    print(G.edges())  # 输出图g的边值
    print(G.in_degree(0))  # node 0 with degree 0

    netx.draw(G)  # 输出一个三角形的图
    plt.show()  # ui显示图形

    g = netx.DiGraph()  # 创建空图
    g.add_edge('a', 'b')  # 插入一条连接a,b的边到图中，节点将自动插入
    g.add_edge('b', 'a')  # 插入一条连接a,b的边到图中，节点将自动插入

    print(g.in_degree("b"))  # node 0 with degree 0


def demo2():
    import networkx as nx
    import matplotlib.pyplot as plt

    # 创建图并添加多个节点和边
    G = nx.Graph()
    G.add_node(1, label="Node 1", description="First node", weight=5)
    G.add_node(2, label="Node 2", description="Second node", weight=3)
    G.add_node(3, label="Node 3", description="Third node", weight=7)
    G.add_node(4, label="Node 4", description="Fourth node", weight=2)
    G.add_node(5, label="Node 5", description="Fifth node", weight=9)

    # 添加一些边
    G.add_edges_from([(1, 2), (1, 3), (2, 4), (3, 5), (4, 5), (1, 4)])

    # 提取标签信息，用于显示在图上
    labels = {}
    for node, data in G.nodes(data=True):
        labels[node] = f"{data['label']}\n{data['description']}\nWeight: {data['weight']}"

    # 绘制图形
    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(G)  # 使用 spring 布局生成节点位置

    # 绘制边（隐藏节点圆点）
    nx.draw_networkx_edges(G, pos)  # 只绘制边，不绘制节点圆点

    # 绘制带边框的节点标签
    ax = plt.gca()
    for node, (x, y) in pos.items():
        label_text = labels[node]
        # 创建文本框并设置位置
        bbox_props = dict(boxstyle="round,pad=0.4", edgecolor="black", facecolor="white", alpha=0.8)
        ax.text(x, y, label_text, ha="center", va="center", fontsize=10, bbox=bbox_props)

    # 保存图片
    plt.title("Network Graph with Only Bounded Content (No Node Circles)")
    plt.savefig("network_with_only_bounded_content.png", format="PNG")
    plt.show()
if __name__ == "__main__":
    # py_graph()
    # py_DiGraph()
    demo2()
