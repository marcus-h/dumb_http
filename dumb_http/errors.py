class ProtocolError(Exception):
    def __init__(self, msg, data=None):
        self.msg = msg
        self.data = data
