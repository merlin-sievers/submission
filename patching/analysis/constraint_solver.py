
class ConstraintSolver:
    def __init__(self, project):
        self.project = project


    def solve(self, slice, jump_target):
        """
        Running the SMTSolver with the Slice of a Control Flow graph and the jump target
        :param slice: The slice of the Control Flow Graph
        :param jump_target: The jump target of the Control Flow Graph
        """

        ssaConverter = new SSAConverter()
        solver = ctx.mkSolver()
        listVariables = new ArrayList < BitVecExpr > ()

        < Register > results = new ArrayList < Register > ()

        Expr operationExpr = null
        # Iterating over the instruction addresses in the slice
        for address in slice:
        #     TODO: Get instruction from somewhere
            block = self.project.factory.block(address)

            # Now iterate over the vex statements of the instruction
            for stmt in block.vex.statements:




        switch(parsedPCode.opCode) {
        case "COPY":
            printf("\n\t parsedPcode %s", parsedPCode.input[0].variableName);

            operationExpr = makeInputVariable(parsedPCode, listVariables, 0, cfg, writingAddr);


            break;

        case
        "INT_ADD":

        operationExpr = ctx.mkBVAdd(makeInputVariable(parsedPCode, listVariables, 0, cfg, writingAddr),
                                    makeInputVariable(parsedPCode, listVariables, 1, cfg, writingAddr));

        break;

        case
        "INT_SUB":

        operationExpr = ctx.mkBVSub(makeInputVariable(parsedPCode, listVariables, 0, cfg, writingAddr),
                                    makeInputVariable(parsedPCode, listVariables, 1, cfg, writingAddr));

        break;

        }}
        // BoolExpr
        equation = ctx.mkEq(operationExpr, makeOutputVariable(parsedPCode, listVariables));
        // equation.simplify();
        solver.add(ctx.mkEq(operationExpr, makeOutputVariable(parsedPCode, listVariables)));

        }

        }

        // Solve
        equation
        system
        so
        that
        it
        jumps
        to
        the
        target
        int
        jumpTargetInt = Integer.parseInt(jumpTarget.toString(), 16);
        printf("\n\t  lastVariable %s", listVariables.get(listVariables.size() - 1));
        solver.add(ctx.mkEq(listVariables.get(listVariables.size() - 1), ctx.mkBV(jumpTargetInt, 32)));

        if (solver.check() == Status.SATISFIABLE)
        {
        // Get
        the
        model
        Model
        model = solver.getModel();

        // Get
        the
        values
        of
        variables
        for (BoolExpr equation: solver.getAssertions()) {
        printf("\n\t %s", equation.toString());
        }

        for (Iterator < Register > itReg = inputs.iterator();itReg.hasNext();) {
        Register relevantRegister = itReg.next();


        printf("\n\t relevant %s", relevantRegister.getName());

        for (FuncDecl decl: model.getDecls()) {

            Expr
        variable = model.eval(decl.apply(), true);
        printf("\n\t DeclName %s", decl.getName());
        if (decl.getName().toString().equals(relevantRegister.getName()))
        {
        printf("\n\t integer %s", Integer.parseInt(variable.toString()));
        if (isPatchMemory) {
        // Need to ADD four since SUB instruction is 4 bit longer than the ADD instruction;
        int subPlusFour = Integer.parseInt(variable.toString());
        subPlusFour = subPlusFour + 4;
        printf("\n\t subvalue %s", subPlusFour);
        relevantRegister.value = subPlusFour;
        results.add(relevantRegister);
        } else {
        relevantRegister.value = Integer.parseInt(variable.toString());
        results.add(relevantRegister);
        }
        }


        printf("\n\t Solution %s ", (decl.getName() + " = " + variable.toString()));
        }
        }
        } else {
            System.out.println("No solution found.");
        }
        solver.reset();
        ctx.close();
        return results;

        }