

class SSAConverter:
    def __init__(self):
        self.used_variables = dict()

    def convert(self, statement):
        if (isElementof(pCode.getInputs(), output)):
            renameVariable(parsedOutput)
        else:
            replaceVariable(parsedOutput)


        parsedPCode.output = parsedOutput;
        parsedPCode.opCode = pCode.getMnemonic();

        return parsedPCode;


# Helper function that renames the variable so that it only gets declared once

    def rename_variable(self, parsed_output):

        if parsed_output in self.used_variables:
            name = str(parsed_output)
            parsed_output.replaceAll("_(.*)", "_" + self.used_variables.get(parsed_output).size())
            self.used_variables[name] = parsed_output
        else:
            name = str(parsed_output)
            parsed_output = parsed_output + "_" + 0
            self.used_variables[name] = parsed_output

# Helper function that replaces an already renamed variable
    def replace_variable(self):

        if (usedVariablesList.containsKey(parsedVarnode.variableName)):
            parsedVarnode.variableName = usedVariablesList.get(parsedVarnode.variableName).get(usedVariablesList.get(parsedVarnode.variableName).size()-1);

