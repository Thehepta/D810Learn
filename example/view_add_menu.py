from ida_kernwin import simplecustviewer_t, attach_action_to_popup, register_action, unregister_action
from ida_kernwin import action_handler_t, action_desc_t

class MyCustomViewer(simplecustviewer_t):
    def __init__(self):
        super().__init__()

    def Create(self):
        # 创建自定义视图
        title = "My Custom Viewer"
        if not super().Create(title):
            return False

        # 填充示例内容
        self.AddLine("Line 1")
        self.AddLine("Line 2")
        self.AddLine("Line 3")
        return True

    def OnPopup(self, widget, popup_handle):
        """
        重写 OnPopup 方法，向右键菜单添加选项
        """
        # 将动作附加到右键菜单
        attach_action_to_popup(widget, popup_handle, "my:action1", None)
        attach_action_to_popup(widget, popup_handle, "my:action2", None)
        return super().OnPopup(widget, popup_handle)

# 定义自定义动作处理程序
class MyActionHandler(action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return 1  # Always enabled

# 注册动作
def register_actions():
    action1 = action_desc_t(
        "my:action1",  # 唯一标识符
        "Option 1",    # 菜单显示名称
        MyActionHandler(lambda: print("Option 1 selected")),
        None,          # 热键
        "Select Option 1",  # 提示信息
        -1             # 图标
    )
    action2 = action_desc_t(
        "my:action2",
        "Option 2",
        MyActionHandler(lambda: print("Option 2 selected")),
        None,
        "Select Option 2",
        -1
    )
    register_action(action1)
    register_action(action2)

def unregister_actions():
    unregister_action("my:action1")
    unregister_action("my:action2")

# 创建视图实例
register_actions()
viewer = MyCustomViewer()
if viewer.Create():
    viewer.Show()
else:
    print("Failed to create viewer")
