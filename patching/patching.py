import angr
import patcherex

from patching.matcher import Matcher


class Patching:
    def __init__(self, patching_config):
        self.patching_config = patching_config


    def patch(self, binary_fname, patch_list, output_fname):
        """
        :param binary_fname: path to the binary to be patched
        :param patch_list: list of patches to be applied
        :param output_fname: path to the patched binary
        :return:
        """
        self.patching_config.start()

        # Find entry point of vulnerable function
        project_vuln = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
        cfg_vuln = project_vuln.analyses.CFGFast()
        entryPoint_vuln = project_vuln.loader.find_symbol(self.patching_config.functionName).rebased_addr

        project_patch = angr.Project("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", auto_load_libs=False)
        cfg_patch = project_patch.analyses.CFGFast()
        entryPoint_patch = project_patch.loader.find_symbol(self.patching_config.functionName).rebased_addr


        # TODO: Translate to python WARNING: Before beginning with patch check if lr has been pushed to the stack
        # if (!(vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains(
        #         "push") & & vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains("lr"))) {
        # printf("\n\t WARNING LR NOT PUSHED TO STACK");
        # }

        binDiffResults = self.patching_config.openBinDiffResults()

        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        perfectMatches = Matcher(cfg_vuln, cfg_patch)

        # Getting all References from both the vulnerable Program and the patch Program

    RefMatc
    er refs =
    new RefMatcher(vulnerableProgram, patchProgram, state, monitor, writer);


    //Match
    g  References if t
    ey are in a perfec
    ly matc
    ed BasicBlock in
    the Function

    matchReferencesFromPerfectMatchedBlocks(perfectMatches, refs);


    //Preparat
    on for writing the Patch in the vulnerable Version

    Matc
    er vulnStartAddress = noPerfectMatchBlocks;
    vulnStartAddress.restrictMatchestoVulnFunction(vulnerableProgram, patchProgram, entryPoint_vuln, entryPoint_patch);


    printf("\n\t vulnStart %s", binDiffResults.equals(vulnStartAddress));

    startAddressofPatch = vulnStartAddress.getSmallestOldAddress();

    CodeBl
    ck codeBlockStart = basicBlockModelOld.getCodeBlockAt(startAddressofPatch, monitor);
    codeBlockEnde = basicBlockModelOld.getCodeBlockAt(vulnStartAddress.getBiggestOldAddress(), monitor);

    patchStartAddressofPatch = vulnStartAddress.getSmallestNewAddress();

    CodeBl
    ck patchCodeBlockStart = basicBlockModelNew.getCodeBlockAt(vulnStartAddress.getSmallestNewAddress(), monitor);
    patchCodeBlockEnde = basicBlockModelNew.getCodeBlockAt(vulnStartAddress.getBiggestNewAddress(), monitor);

    patchSize = getPatchSize(vulnStartAddress);

    //printf("\n\t Schritt 1 %s ", patchCodeBlockStrt );
    //GhidraScr
    pt speci
    ic Coe. T
    is chan
    es
    the Prog
    am that is shown in
    the GUI and enab
    es
    us
    to wr
    te
    to
    the vulnerableProgram
    end(true);
    set(vulnerableProgram, monitor);
    start();



// St
rt
of
the act
al patching:

// Cre
te a
new mem
ry sect
on
to wr
te
the pa
ch into
patchMemory =
new NewMemory(vulnerableProgram, ".patch", state, monitor, writer);

//TODO: Where is t
is actua
ly needed?
L i st<Addr ess> ldrAddress =
new ArrayL is t<>();

//Preparati
ns
to
be a
le
to
get
the analy
ed programs
List
ng listing = vulnerableProgram.getListing();
List
ng listingneu = patchProgram.getListing();

//J
mp
to
new Memory
jumpToNewMemory(codeBlockStart, patchCodeBlockStart);

Addr
ss pCBStart = patchCodeBlockStart.getFirstStartAddress();

while (pCBStart.compareTo(patchCodeBlockEnde.getFirstStartAddress().next()) == -1) {


// Some GhidraScript specific preparations
// Assumption CodeUnitIterator stable even if listing gets modified
// printf("\n\t Codeunititerator0");

CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlockStart, true);


CodeUnit codun = null;
CodeUnit codunneu = null;
codunaddr = null;

// Going through every CodeUnit from the BasicBlock for(codeUnitIteratorneu = listingneu.getCodeUnits(patchCodeBlockStart, true); codeUnitIteratorneu.hasNext(); ){
/ /printf("\n\t Codeunititerator1 ");

codunneu = codeUnitIteratorneu.next();
// Rewriting of  patch codeUnit to the vulnerable Version, if it is not part of a perfectly matched Block
printf("\n\t codunneu %s", codunneu);
codun = codeUnitIterator.next();
if (next == null) {
next = patchMemory.freeAddress;
}

codunaddr = next;
printf("\n\t Addresse %s", codunaddr);

i f(codunaddr.equals(toAddr("0x1c6380"))) {
return;
}

//				Uncomment the following to use Angr References
Reference[] datref = getAngrReference(codunneu);

//				Uncomment the following to use Ghidra References
                                                        //				Reference[] datref = codunneu.getReferencesFrom();

/ /Handling of possible References
i f(datref.length >0)
{
printf("\n\t Reference beginning:", datref[0].getFromAddress());
handleReferences(datref, refs, codun, codunneu, ldrAddress);
} else {
printf("\n \t No Reference");
rewritingBytesofCodeUnitToNewAddress(codunneu, codunaddr);
next = codunaddr.add(codunneu.getLength());
}
}

codeBlockStart = basicBlockModelOld.getCodeBlockAt(codeBlockStart.getMaxAddress().next(), monitor);

patchCodeBlockStart = basicBlockModelNew.getCodeBlockAt(patchCodeBlockStart.getMaxAddress().next(), monitor);

if (patchCodeBlockStart == null)
{
    pCBStart = patchCodeBlockEnde.getMaxAddress();
} else {
    pCBStart = patchCodeBlockStart.getFirstStartAddress();
}

}
// Set
the
End
for the last ShiftZone
shiftsAscending.get(shiftsAscending.size()-1).end = next;
shiftsDescending.get(shiftsDescending.size()-1).end = next;

// Fix all References broken by shifts
fixShiftsInReferences();

// Jump back to the original function since the patch is now integrated

if (!(next.subtract(codeBlockEnde.getMaxAddress().next()) % 4 == 0)) {

byte[] test = new byte[2];
test[0] = (byte) 0x00;
test[1] = (byte) 0xbf;
printf("\n \t nop1 next %s", next);

// setBytes(next, test);

asmVuln.patchProgram(test, next);
Disassembler disasm = Disassembler.getDisassembler(vulnerableProgram, monitor, null);

// Dissassemble correctly in ArmThumbMode
clearListing(next, next.add(2));
ArmDisassembleCommand arws = new ArmDisassembleCommand(next, new AddressSet(next), true);
arws.applyTo(vulnerableProgram);
disasm.disassemble(next, new AddressSet(next));

next = next.add(2);
}

clearListing(next, next.add(4));
printf("\n\t Codunaddr %s", next);
asmVuln.assemble(next, "bl 0x" + codeBlockEnde.getMaxAddress().next());

}