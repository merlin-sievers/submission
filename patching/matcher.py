class Matcher:
    def __init__(self, cfg_vuln, cfg_patch):
        self.matchOldAddress=dict()
        self.matchNewAddress=dict()

        for node in cfg_vuln.graph.nodes:
            self.matchOldAddress[node.addr]=

        # Get SQLResults in some way

        # Get all perfect Matches of BasicBlocks from the BinDiffResults