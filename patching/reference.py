class Reference:
    def __init__(self, fromAddr, toAddr, refType):
        self.fromAddr = fromAddr
        self.toAddr = toAddr
        self.refType = refType


class TrackingRegister:
    def __init__(self, register_name, ldr_data_address, old_ldr_data_address):
        self.register_name = register_name
        self.ldr_data_address = ldr_data_address
        self.old_ldr_data_address = old_ldr_data_address