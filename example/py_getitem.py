class DataBase:
    '''Python 3 中的类'''

    def __init__(self, id, address):
        '''初始化方法'''
        self.id = id
        self.address = address
        self.d = {self.id: 1,
                  self.address: "192.168.1.1",
                  }

    def __getitem__(self, key):
        # return self.__dict__.get(key, "100")
        return self.d.get(key, "default")


data = DataBase(1, "192.168.2.11")
print(data["hi"])
print(data[data.id])
