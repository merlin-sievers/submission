import pyvex.stmt
import z3
from angr.sim_variable import SimTemporaryVariable


# Assumptions Vex is only in SSA Form inside of a basic block.
class ConstraintSolver:
    def __init__(self, project, start_address):
        self.project = project
        self.ctx = z3.Context()
        self.solver = z3.Solver()
        self.variables = []
        self.results = []

        self.basic_block_ssa = "b"
        self.register_ssa = dict()
        self.used_registers = []
        self.start_address = start_address

        self._vex_expr_handlers = []
        self._vex_stmt_handlers = []
        self.__init_handlers()



    def __init_handlers(self):
        self._vex_expr_handlers = [None] * pyvex.expr.tag_count
        self._vex_stmt_handlers = [None] * pyvex.stmt.tag_count
        for name, cls in vars(pyvex.expr).items():
            if isinstance(cls, type) and issubclass(cls, pyvex.expr.IRExpr) and cls is not pyvex.expr.IRExpr:
                self._vex_expr_handlers[cls.tag_int] = getattr(self, "_handle_vex_expr_" + name)
        for name, cls in vars(pyvex.stmt).items():
            if isinstance(cls, type) and issubclass(cls, pyvex.stmt.IRStmt) and cls is not pyvex.stmt.IRStmt:
                self._vex_stmt_handlers[cls.tag_int] = getattr(self, "_handle_vex_stmt_" + name)
        assert None not in self._vex_expr_handlers
        assert None not in self._vex_stmt_handlers

    def solve(self, slice, jump_target, writing_address, variable, written_registers):
        """
        Running the SMTSolver with the Slice of a Control Flow graph and the jump target
        :param slice: The slice of the Control Flow Graph
        :param jump_target: The jump target of the Control Flow Graph
        :param writing_address: The address where the jump instruction is written to
        :param variable: The variable that is used to jump to the target
        :param written_registers: The registers that are used in the slice that already have an assigned value
        """
        results = []
        i = 0
        self.basic_block_ssa = "b"
        self.variable = variable
        # Iterating over the instruction addresses in the slice
        for address, ids in sorted(slice.items()):
            block = self.project.factory.block(address, size=75)
            block.pp()
            print("Address", hex(address))
            # nodes = self.project.kb.cfgs.cfgs["CFGEmulated"].get_all_nodes(address)
            # largest_node = max(nodes, key=lambda node: node.size)
            # block = largest_node.block


            self.basic_block_ssa = str(i) + "b"
            i = i+1
            # Now iterate over the vex statements of the instruction
            for id, ins_addr in sorted(ids):

                if block.thumb:
                    ins_addr = ins_addr - 1
            #TODO BAD HACK CHANGE IT!!!
                if(len(block.vex.statements) > id):
                    statement = block.vex.statements[id]
                else:
                    print("it happened again")
                    continue

                if self.handle_vex_statement(statement, ins_addr, writing_address):
                    # To debug solver we need to push the assertions
                    # self.solver.push()
                    continue
                else:
                    break

        # Solve equation system so that it jumps to the target


        new_target = z3.BitVecVal(jump_target, 32)

        if self.variables == []:
            return None

        if isinstance(variable, SimTemporaryVariable):

            for k in range(i, -1, -1):
                register = z3.BitVec("t" + str(k) + "b" + str(variable.tmp_id), 32)
                if register in self.variables:
                    break
        else:
            for k in range(i, -1, -1):
                register = z3.BitVec("r" + str(k) + "b" + str(variable.reg), 32)
                if register in self.variables:
                    break
                else:
                    register = z3.BitVec("r" + str(variable.reg), 32)

        if len(self.used_registers) == 0:
            self.used_registers.append(register)


        self.solver.add(self.used_registers[0] == new_target)


        # Add Constraints for already written values in the registers
        for reg in written_registers:
            var = z3.BitVec(str(reg), 32)
            expr = z3.BitVecVal(written_registers[reg], 32)
            self.solver.add(var == expr)


        if self.solver.check() == z3.sat:
        # Get the model
            print("solvable")
            model = self.solver.model()
        # Get the values of variables
        #     for itReg in inputs:
        #         relevantRegister = itReg
        #     for equation in self.solver.assertions():
                # print("\n\t", equation)

            for decl in model.decls():

                variable = model.eval(decl(), True)
                # print("var\n\t", decl, variable)
                result = (decl, variable)
                results.append(result)

        return results


    def handle_vex_statement(self, stmt: pyvex.stmt.IRStmt, address, writing_address):
        handler = self._vex_stmt_handlers[stmt.tag_int]
        handler(stmt, address, writing_address)
        return True



    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr, address, writing_address):
        handler = self._vex_expr_handlers[expr.tag_int]
        return handler(expr, address, writing_address)


    # Statement Handlers
    def _handle_vex_stmt_IMark(self, statement, address, writing_address):
        if statement.addr == address:
            return True
        else:
            return False


    def _handle_vex_stmt_NoOp(self, statement, address, writing_address):
        pass


    def _handle_vex_stmt_AbiHint(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_WrTmp(self, statement, address, writing_address, ):
        tmp = z3.BitVec("t" + self.basic_block_ssa + str(statement.tmp), 32)
        self.variables.append(tmp)
        expression = self._handle_vex_expr(statement.data, address, writing_address)
        if expression != None:
            self.solver.add(tmp == expression)
        return True

    def _handle_vex_stmt_Put(self, statement, address, writing_address):
        register = z3.BitVec("r" + str(statement.offset), 32)
        if register in self.register_ssa:
            register_new = z3.BitVec("r" + self.basic_block_ssa + str(statement.offset), 32)
            self.register_ssa[register].append(register_new)
            register = register_new

        else:
            self.register_ssa[register] = [register]

        if address == self.start_address:
            if self.variable is not SimTemporaryVariable:
                if statement.offset == self.variable.reg:
                    self.used_registers.append(register)

        self.variables.append(register)
        expression = self._handle_vex_expr(statement.data, address, writing_address)
        self.solver.add(register == expression)
        return True


    def _handle_vex_stmt_PutI(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_Store(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_LoadG(self, statement, address, writing_address):
        if statement.addr.tag_int == 11:
            load = z3.BitVec(str(statement.addr), 32)
        else:
            load = self._handle_vex_expr(statement.addr, address, writing_address)
        alt = self._handle_vex_expr(statement.alt, address, writing_address)
        guard = self._handle_vex_expr(statement.guard, address, writing_address)
        tmp = z3.BitVec("t" + self.basic_block_ssa + str(statement.dst), 32)
        condition = z3.If(guard != 0, load, alt)
        self.variables.append(tmp)
        self.solver.add(tmp == condition)
        return True

    def _handle_vex_stmt_StoreG(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_CAS(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_LLSC(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_Dirty(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_MBE(self, statement, address, writing_address):
        pass

    def _handle_vex_stmt_Exit(self, statement, address, writing_address):
        pass




    # Expression Handlers


    def _handle_vex_expr_Binder(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_Get(self, expression, address, writing_address):
        register = z3.BitVec("r" + str(expression.offset), 32)
        if register in self.register_ssa:
            register = self.register_ssa[register][-1]
        self.variables.append(register)
        return register

    def _handle_vex_expr_GetI(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_RdTmp(self, expression, address, writing_address):
        variable = z3.BitVec("t" + self.basic_block_ssa + str(expression.tmp), 32)
        self.variables.append(variable)
        return variable
    def _handle_vex_expr_Qop(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_Triop(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_Binop(self, expression, address, writing_address):
        op1 = self._handle_vex_expr(expression.args[0], address, writing_address)
        self.variables.append(op1)
        op2 = self._handle_vex_expr(expression.args[1], address, writing_address)
        self.variables.append(op2)
        if expression.op == "Iop_Add32":
            expr = op1 + op2
            return expr
        if expression.op == "Iop_CmpNE32":
            expr = op1 - op2
            return expr
        if expression.op == "Iop_And32":
            expr = op1 & op2
            return expr
        if expression.op == "Iop_Or32":
            expr = op1 | op2
            return expr
        if expression.op == "Iop_Shr32":
            expr = z3.LShR(op1, op2)
            return expr
        if expression.op == "Iop_Xor32":
            expr = op1 ^ op2
            return expr


    def _handle_vex_expr_Unop(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_Load(self, expression, address, writing_address):
        load = z3.BitVec(str(expression.addr), 32)
        self.variables.append(load)
        return load

    # TODO: Validate that i consider every constant bigger than 20000 to be an address//  Could use the entry point of the program here...
    def _handle_vex_expr_Const(self, expression, address, writing_address):
        new_address = expression.con.value + writing_address - self.start_address
        if expression.con.value > 20000:
            expr = z3.BitVecVal(new_address, 32)
        else:
            expr = z3.BitVecVal(expression.con.value, 32)
        return expr

    def _handle_vex_expr_ITE(self, expression, address, writing_address):
        cond = self._handle_vex_expr(expression.cond, address, writing_address)
        true = self._handle_vex_expr(expression.iftrue, address, writing_address)
        self.variables.append(true)
        false = self._handle_vex_expr(expression.iffalse, address, writing_address)
        self.variables.append(false)
        condition = z3.If(cond != 0, true, false)
        return condition

    def _handle_vex_expr_CCall(self, expression, address, writing_address):
        expression = z3.BitVecVal(1, 32)
        return expression

    def _handle_vex_expr_VECRET(self, expression, address, writing_address):
        pass

    def _handle_vex_expr_GSPTR(self, expression, address, writing_address):
        pass