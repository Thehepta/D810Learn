# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.



class GenericDispatcherBlockInfo(object):

    def __init__(self, str):
        self.string = str

    def register_father(self, father: 'GenericDispatcherBlockInfo'):
        print(father.string)



def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    gen = GenericDispatcherBlockInfo("321321321")
    gen2 = GenericDispatcherBlockInfo("11111")
    gen2.register_father(gen);
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
