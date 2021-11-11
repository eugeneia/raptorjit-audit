local ffi = require("ffi")
local band, rshift = bit.band, bit.rshift

-- LuaJIT bytecode

-- bytecode:from_prototype (Prototype, number) -> Bytecode
--    Parse Bytecode from Prototype at offset.

local Bytecode = {}

local Operands = {
   var = "variable slot number",
   dst = "variable slot number, used as a destination",
   base = "base slot number, read-write",
   rbase = "base slot number, read-only",
   uv = "upvalue number",
   lit = "literal",
   lits = "signed literal",
   pri = "primitive type (0 = nil, 1 = false, 2 = true)",
   num = "number constant, index into constant table",
   str = "string constant, negated index into constant table",
   tab = "template table, negated index into constant table",
   func = "function prototype, negated index into constant table",
   cdata = "cdata constant, negated index into constant table",
   jump = "branch target, relative to next instruction, biased with 0x8000"
}

local Operators = {
   -- Comparison ops
   ISLT = {a="var", d="var", hint="Jump if A < D"},
   ISGE = {a="var", d="var", hint="Jump if A ≥ D"},
   ISLE = {a="var", d="var", hint="Jump if A ≤ D"},
   ISGT = {a="var", d="var", hint="Jump if A > D"},
   ISEQV = {a="var", d="var", hint="Jump if A = D"},
   ISNEV = {a="var", d="var", hint="Jump if A ≠ D"},
   ISEQS = {a="var", d="str", hint="Jump if A = D"},
   ISNES = {a="var", d="str", hint="Jump if A ≠ D"},
   ISEQN = {a="var", d="num", hint="Jump if A = D"},
   ISNEN = {a="var", d="num", hint="Jump if A ≠ D"},
   ISEQP = {a="var", d="pri", hint="Jump if A = D"},
   ISNEP = {a="var", d="pri", hint="Jump if A ≠ D"},
   -- Unary Test and Copy ops
   ISTC = {a="dst", d="var", hint="Copy D to A and jump, if D is true"},
   ISFC = {a="dst", d="var", hint="Copy D to A and jump, if D is false"},
   IST = {d="var", hint="Jump if D is true"},
   ISF = {d="var", hint="Jump if D is false"},
   ISTYPE = {a="var", d="lit", hint="Assert that A has type -D"},
   ISNUM = {a="var", hint="Assert that A is a number"},
   -- Unary ops
   MOV = {a="dst", d="var", hint="Copy D to A"},
   NOT = {a="dst", d="var", hint="Set A to boolean not of D"},
   UNM = {a="dst", d="var", hint="Set A to -D (unary minus)"},
   LEN = {a="dst", d="var", hint="Set A to #D (object length)"},
   -- Binary ops
   ADDVN = {a="dst", b="var", c="num", hint="A = B + C"},
   SUBVN = {a="dst", b="var", c="num", hint="A = B - C"},
   MULVN = {a="dst", b="var", c="num", hint="A = B * C"},
   DIVVN = {a="dst", b="var", c="num", hint="A = B / C"},
   MODVN = {a="dst", b="var", c="num", hint="A = B % C"},
   ADDNV = {a="dst", b="var", c="num", hint="A = C + B"},
   SUBNV = {a="dst", b="var", c="num", hint="A = C - B"},
   MULNV = {a="dst", b="var", c="num", hint="A = C * B"},
   DIVNV = {a="dst", b="var", c="num", hint="A = C / B"},
   MODNV = {a="dst", b="var", c="num", hint="A = C % B"},
   ADDVV = {a="dst", b="var", c="var", hint="A = B + C"},
   SUBVV = {a="dst", b="var", c="var", hint="A = B - C"},
   MULVV = {a="dst", b="var", c="var", hint="A = B * C"},
   DIVVV = {a="dst", b="var", c="var", hint="A = B / C"},
   MODVV = {a="dst", b="var", c="var", hint="A = B % C"},
   POW = {a="dst", b="var", c="var", hint="A = B ^ C"},
   CAT = {a="dst", b="rbase", c="rbase", hint="A = B .. ~ .. C"},
   -- Constant ops
   KSTR = {a="dst", d="str", hint="Set A to string constant D"},
   KCDATA = {a="dst", d="cdata", hint="Set A to cdata constant D"},
   KSHORT = {a="dst", d="lits", hint="Set A to 16 bit signed integer D"},
   KNUM = {a="dst", d="num", hint="Set A to number constant D"},
   KPRI = {a="dst", d="pri", hint="Set A to primitive D"},
   KNIL = {a="base", d="base", hint="Set slots A to D to nil"},
   -- Upvalue and Function ops
   UGET = {a="dst", d="uv", hint="Set A to upvalue D"},
   USETV = {a="uv", d="var", hint="Set upvalue A to D"},
   USETS = {a="uv", d="str", hint="Set upvalue A to string constant D"},
   USETN = {a="uv", d="num", hint="Set upvalue A to number constant D"},
   USETP = {a="uv", d="pri", hint="Set upvalue A to primitive D"},
   UCLO = {a="rbase", d="jump", hint="Close upvalues for slots ≥ rbase and jump to target D"},
   FNEW = {a="dst", d="func", hint="Create new closure from prototype D and store it in A"},
   -- Table ops
   TNEW = {a="dst", d="lit", hint="Set A to new table with size D (see below)"},
   TDUP = {a="dst", d="tab", hint="Set A to duplicated template table D"},
   GGET = {a="dst", d="str", hint="A = _G[D]"},
   GSET = {a="var", d="str", hint="_G[D] = A"},
   TGETV = {a="dst", b="var", c="var", hint="A = B[C]"},
   TGETS = {a="dst", b="var", c="str", hint="A = B[C]"},
   TGETB = {a="dst", b="var", c="lit", hint="A = B[C]"},
   TGETR = {a="dst", b="var", c="lit", hint="A = B[C] (rawget)"},
   TSETV = {a="var", b="var", c="var", hint="B[C] = A"},
   TSETS = {a="var", b="var", c="str", hint="B[C] = A"},
   TSETB = {a="var", b="var", c="lit", hint="B[C] = A"},
   TSETR = {a="var", b="var", c="lit", hint="B[C] = A (rawset)"},
   TSETM = {a="base", d="num", hint="(A-1)[D], (A-1)[D+1], ... = A, A+1, ..."},
   -- Calls and Vararg Handling
   CALLM = {a="base",b="lit", c="lit", hint="Call: A, ..., A+B-2 = A(A+1, ..., A+C+MULTRES)"},
   CALL = {a="base",b="lit", c="lit", hint="Call: A, ..., A+B-2 = A(A+1, ..., A+C-1)"},
   CALLMT = {a="base", d="lit", hint="Tailcall: return A(A+1, ..., A+D+MULTRES)"},
   CALLT = {a="base", d="lit", hint="Tailcall: return A(A+1, ..., A+D-1)"},
   ITERC = {a="base",b="lit", c="lit", hint="Call iterator: A, A+1, A+2 = A-3, A-2, A-1; A, ..., A+B-2 = A(A+1, A+2)"},
   ITERN = {a="base",b="lit", c="lit", hint="Specialized ITERC, if iterator function A-3 is next()"},
   VARG = {a="base",b="lit", c="lit", hint="Vararg: A, ..., A+B-2 = ..."},
   ISNEXT = {a="base", d="jump", hint="Verify ITERN specialization and jump"},
   -- Returns
   RETM = {a="base", d="lit", hint="return A, ..., A+D+MULTRES-1"},
   RET = {a="rbase", d="lit", hint="return A, ..., A+D-2"},
   RET0 = {a="rbase", d="lit", hint="return"},
   RET1 = {a="rbase", d="lit", hint="return A"},
   -- Loops and branches
   FORI = {a="base", d="jump", hint="Numeric 'for' loop init"},
   JFORI = {a="base", d="jump", hint="Numeric 'for' loop init, JIT-compiled"},
   FORL = {a="base", d="jump", hint="Numeric 'for' loop"},
   IFORL = {a="base", d="jump", hint="Numeric 'for' loop, force interpreter"},
   JFORL = {a="base", d="lit", hint="Numeric 'for' loop, JIT-compiled"},
   ITERL = {a="base", d="jump", hint="Iterator 'for' loop"},
   IITERL = {a="base", d="jump", hint="Iterator 'for' loop, force interpreter"},
   JITERL = {a="base", d="lit", hint="Iterator 'for' loop, JIT-compiled"},
   LOOP = {a="rbase", d="jump", hint="Generic loop"},
   ILOOP = {a="rbase", d="jump", hint="Generic loop, force interpreter"},
   JLOOP = {a="rbase", d="lit", hint="Generic loop, JIT-compiled"},
   JMP = {a="rbase", d="jump", hint="Jump"},
   -- Function headers
   FUNCF = {a="rbase", hint="Fixed-arg Lua function"},
   IFUNCF = {a="rbase", hint="Fixed-arg Lua function, force interpreter"},
   JFUNCF = {a="rbase", d="lit", hint="Fixed-arg Lua function, JIT-compiled"},
   FUNCV = {a="rbase", hint="Vararg Lua function"},
   IFUNCV = {a="rbase", hint="Vararg Lua function, force interpreter"},
   JFUNCV = {a="rbase", d="lit", hint="Vararg Lua function, JIT-compiled"},
   FUNCC = {a="rbase", hint="Pseudo-header for C functions"},
   FUNCCW = {a="rbase", hint="Pseudo-header for wrapped C functions"},
}

function nop () end
function lits (bc, o)
   bc[o] = tonumber(ffi.cast('int16_t', bc[o]))
end
function pri (bc, o)
   bc[o] = assert(({[0]='nil', [1]='false', [2]='true'})[bc[o]])
end
function jump (bc, o)
   bc.j = bc[o] - 0x8000 -- BCBIAS_J
   bc[o] = nil
end

local ParseOperand = {
   var = nop,
   dst = nop,
   base = nop,
   rbase = nop,
   uv = nop,
   lit = nop,
   lits = lits,
   pri = pri,
   num = nop,
   str = nop,
   tab = nop,
   func = nop,
   cdata = nop,
   jump = jump
}

function Bytecode:from_prototype (proto, pos)
   assert(pos < proto.GCproto.sizebc)
   local bc = proto.bytecodes[pos]
   local ret = {
      op = band(bc, 0xff),
      a = band(rshift(bc,  8), 0xff),
      b = band(rshift(bc, 24), 0xff),
      c = band(rshift(bc, 16), 0xff),
      d = band(rshift(bc, 16), 0xffff)
   }
   local opcode = ffi.cast(proto.bcop_t, ret.op)
   ret.name = proto.auditlog.dwarf:enum_name(opcode):match("BC_(.*)")
   local spec = Operators[ret.name]
   if not spec then
      ret.hint = "Unknown bytecode"
      return ret
   end
   ret.hint = spec.hint
   for _, operand in ipairs{'a', 'b', 'c', 'd'} do
      if spec[operand] then
         assert(ParseOperand[spec[operand]])(ret, operand) -- XXX const
      else
         ret[operand] = nil
      end
   end
   return ret   
end

-- Module bytecode

return Bytecode
