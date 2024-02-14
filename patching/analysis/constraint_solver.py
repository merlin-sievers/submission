import pyvex.stmt
import z3

# TODO: Make sure that SSA transformation is not necessary
class ConstraintSolver:
    def __init__(self, project):
        self.project = project
        self.ctx = z3.Context()
        self.solver = z3.Solver()
        self.variables = []
        self.results = []

    def solve(self, slice, jump_target, writing_address):
        """
        Running the SMTSolver with the Slice of a Control Flow graph and the jump target
        :param slice: The slice of the Control Flow Graph
        :param jump_target: The jump target of the Control Flow Graph
        """
        results = []
        # Iterating over the instruction addresses in the slice
        for address, ids in slice.items():
            block = self.project.factory.block(address)
            # Check if the instruction is a thumb instruction
            if block.thumb:
                address = address - 1
            # Now iterate over the vex statements of the instruction
            for id, ins_addr in ids:
                statement = block.vex.statements[id]
                if self.handle_vex_statement(statement, ins_addr, writing_address):
                    continue
                else:
                    break

        # Solve equation system so that it jumps to the target

        new_target = z3.BitVecVal(jump_target, 32)
        print(self.variables[len(self.variables)-1])
        if self.variables == []:
            return None
        self.solver.add(self.variables[len(self.variables)-1] == new_target)

        if self.solver.check() == z3.sat:
        # Get the model
            print("solvable")
            model = self.solver.model()
        # Get the values of variables
        #     for itReg in inputs:
        #         relevantRegister = itReg
            for equation in self.solver.assertions():
                print("\n\t", equation)

            for decl in model.decls():

                variable = model.eval(decl(), True)

                result = (decl, variable)
                results.append(result)

        return results


        #             if (isPatchMemory):
        # #  Need to ADD four since SUB instruction is 4 bit longer than the ADD instruction;
        #                 subPlusFour = Integer.parseInt(variable.toString())
        #                 subPlusFour = subPlusFour + 4
        #
        #                 relevantRegister.value = subPlusFour
        #                 results.add(relevantRegister)
        #             else:
        #                 relevantRegister.value = Integer.parseInt(variable.toString())
        #                 results.add(relevantRegister)


    def handle_vex_statement(self, statement, address, writing_address):
        if isinstance(statement, pyvex.stmt.IMark):
            return self._handle_vex_IMark_statement(statement, address)
        elif isinstance(statement, pyvex.stmt.WrTmp):
            return self._handle_vex_WrTmp_statement(statement, address, writing_address)
        elif isinstance(statement, pyvex.stmt.Put):
            return self._handle_vex_Put_statement(statement)

    def _handle_vex_IMark_statement(self, statement, address):
        if statement.addr == address:
            return True
        else:
            return False

    def _handle_vex_WrTmp_statement(self, statement, address, writing_address):
        # Handle t1 = GET:I32(r1)
        if isinstance(statement.data, pyvex.expr.Get):
            temp = z3.BitVec("t" + str(statement.tmp), 32)
            register = z3.BitVec("r" + str(statement.data.offset), 32)
            self.solver.add(temp == register)
            self.variables.append(register)
            self.variables.append(temp)

        # Handle t1 = LDle:I32(0x00000)
        if isinstance(statement.data, pyvex.expr.Load):
            temp = z3.BitVec("t" + str(statement.tmp), 32)
            load = z3.BitVec(str(statement.data.addr), 32)
            self.solver.add(temp == load)
            self.variables.append(load)
            self.variables.append(temp)

        # Handle t1 = Add32(t56,0x00000000)
        if isinstance(statement.data, pyvex.expr.Binop):
            temp = z3.BitVec("t" + str(statement.tmp), 32)
            op1 = z3.BitVec(str(statement.data.args[0]), 32)
            new_address = statement.data.args[1].con.value - address + writing_address
            op2 = z3.BitVecVal(new_address, 32)
            if statement.data.op == "Iop_Add32":
                self.solver.add(temp == op1 + op2)
            self.variables.append(temp)

        return True

    def _handle_vex_Put_statement(self, statement):
        register = z3.BitVec("r" + str(statement.offset), 32)
        # Handle Put(offset=12) = t1
        if isinstance(statement.data, pyvex.expr.RdTmp):
            variable = z3.BitVec("t" + str(statement.data.tmp), 32)
        # Handle Put(offset=12) = 0x00000000
        elif isinstance(statement.data, pyvex.expr.Const):
            variable = z3.BitVecVal(statement.data.con.value, 32)
        else:
            variable = z3.BitVec("t", 32)
        self.variables.append(variable)
        self.variables.append(register)
        self.solver.add(register == variable)
        return True
