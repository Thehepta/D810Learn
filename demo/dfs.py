#一个有循环的流程图，给定一个节点，深度遍历所有的分支，找到所有的可到达这个节点的路径，给定的节点和目标节点是一个节点，用于寻找循环

from collections import defaultdict

class Graph:
    def __init__(self):
        self.graph = defaultdict(list)

    def add_edge(self, u, v):
        self.graph[u].append(v)

    def find_cycles(self, start_node):
        paths = []
        self.dfs(start_node, start_node, [], paths, set())
        return paths

    def dfs(self, current_node, target_node, path, paths, visited):
        path.append(current_node)
        visited.add(current_node)

        for neighbor in self.graph[current_node]:
            if neighbor == target_node and len(path) > 1:
                paths.append(list(path))
            elif neighbor not in visited:
                self.dfs(neighbor, target_node, path, paths, visited)

        path.pop()
        visited.remove(current_node)

# 示例用法
if __name__ == "__main__":
    g = Graph()
    g.add_edge('A', 'B')
    g.add_edge('B', 'C')
    g.add_edge('C', 'A')  # 形成循环
    g.add_edge('B', 'D')
    g.add_edge('D', 'B')  # 形成循环
    g.add_edge('A', 'G')  # 形成循环
    g.add_edge('G', 'H')  # 形成循环
    g.add_edge('H', 'A')  # 形成循环

    start_node = 'A'
    cycles = g.find_cycles(start_node)
    print("所有包含目标节点的循环路径：")
    for path in cycles:
        print(" -> ".join(path))