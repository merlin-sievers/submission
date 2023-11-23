
class Shift:
    def __init__(self):
        self.start = None
        self.end = None
        self.shifted_bytes = 0

    def biggerThanShiftZone(self, ref):
        if ref <= self.start:
            return 0
        return self.shifted_bytes

    def smallerThanShiftZone(self, ref):
        if ref < self.start:
            return self.shifted_bytes
        return 0

    def isInsideShiftZone(self, ref):
        if ref < self.start:
            return False
        if ref > self.end:
            return False
        return True
