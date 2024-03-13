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

        self._vex_expr_handlers = []
        self._vex_stmt_handlers = []
        self.__init_handlers()

        self.irsb = None
        self.stmt_idx = None
        self.tmps = None

    #    Helper
        self.helper_variable = None
        self.helper_register = None


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


    def handle_vex_statement(self, stmt: pyvex.stmt.IRStmt, address, writing_address):
        handler = self._vex_stmt_handlers[stmt.tag_int]
        handler(stmt, address, writing_address)
        return True

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr, address, writing_address, tmp):
        handler = self._vex_expr_handlers[expr.tag_int]
        handler(expr, address, writing_address, tmp)



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

    def _handle_vex_stmt_WrTmp(self, statement, address, writing_address):
        tmp = z3.BitVec("t" + str(statement.tmp), 32)
        self._handle_vex_expr(statement.data, address, writing_address, tmp)
        return True

    def _handle_vex_stmt_Put(self, statement, address, writing_address):
        register = z3.BitVec("r" + str(statement.offset), 32)
        self._handle_vex_expr(statement.data, address, writing_address, tmp=None)
        self.variables.append(register)
        self.variables.append(self.helper_variable)
        self.solver.add(register == self.helper_variable)
        return True


    def _handle_vex_stmt_PutI(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_Store(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_LoadG(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_StoreG(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_CAS(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_LLSC(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_Dirty(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_MBE(self, statement, address, writing_address):
        return NotImplemented

    def _handle_vex_stmt_Exit(self, statement, address, writing_address):
        return NotImplemented




    # Expression Handlers


    def _handle_vex_expr_Binder(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_Get(self, expression, address, writing_address, tmp):
        register = z3.BitVec("r" + str(expression.offset), 32)
        self.solver.add(tmp == register)
        self.variables.append(register)
        self.variables.append(tmp)

    def _handle_vex_expr_GetI(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_RdTmp(self, expression, address, writing_address, tmp):
        self.helper_variable = z3.BitVec("t" + str(expression.tmp), 32)

    def _handle_vex_expr_Qop(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_Triop(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_Binop(self, expression, address, writing_address, tmp):
        self._handle_vex_expr(expression.args[0], address, writing_address, tmp)
        op1 = self.helper_variable
        self._handle_vex_expr(expression.args[1], address, writing_address, tmp)
        op2 = self.helper_variable
        if expression.op == "Iop_Add32":
            self.solver.add(tmp == op1 + op2)

        if expression.op == "CmpNE32":
            self.solver.add(tmp == op1 - op2)
        self.variables.append(tmp)

    def _handle_vex_expr_Unop(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_Load(self, expression, address, writing_address, tmp):
        load = z3.BitVec(str(expression.addr), 32)
        self.solver.add(tmp == load)
        self.variables.append(load)
        self.variables.append(tmp)
    # TODO: Validate that i consider every constant bigger than 20000 to be an address
    def _handle_vex_expr_Const(self, expression, address, writing_address, tmp):
        new_address = expression.con.value - address + writing_address
        if expression.con.value > 20000:
            self.helper_variable = z3.BitVecVal(new_address, 32)
        else:
            self.helper_variable = z3.BitVecVal(expression.con.value, 32)


    def _handle_vex_expr_ITE(self, expression, address, writing_address, tmp):
        self._handle_vex_expr(expression.cond, address, writing_address, tmp)
        cond = self.helper_variable
        self._handle_vex_expr(expression.iftrue, address, writing_address, tmp)
        true = self.helper_variable
        self._handle_vex_expr(expression.iffalse, address, writing_address, tmp)
        false = self.helper_variable
        condition = z3.If(cond == 0, true, false)
        self.solver.add(tmp == condition)
        return NotImplemented

    def _handle_vex_expr_CCall(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_VECRET(self, expression, address, writing_address, tmp):
        return NotImplemented

    def _handle_vex_expr_GSPTR(self, expression, address, writing_address, tmp):
        return NotImplemented

