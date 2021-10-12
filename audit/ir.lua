local ffi = require("ffi")
local band, lshift, rshift = bit.band, bit.lshift, bit.rshift

-- LuaJIT IR

local IR = {}

local Opcodes = {
   lt = 'LT (left, right): left < right (signed)',
   ge = 'GE (left, right): left >= right (signed)',
   le = 'LE (left, right): left <= right (signed)',
   gt = 'GT (left, right): left > right (signed)',
   ult = 'ULT (left, right): left < right (unsigned/unordered)',
   uge = 'UGE (left, right): left >= right (unsigned/unordered)',
   ule = 'ULE (left, right): left <= right (unsigned/unordered)',
   ugt = 'UGT (left, right): left > right (unsigned/unordered)',
   eq = 'EQ (left, right): left = right',
   ne = 'NE (left, right): left ~= right',
   abc = 'ABC (bound, index): Array Bounds Check: bound > index (unsigned)',
   retf = 'RETF (proto, pc): Return to lower frame: check target PC, shift base',
   bnot = 'BNOT (ref): Bitwise NOT of ref',
   bswap = 'BSWAP (ref): Byte-swapped ref',
   band = 'BAND (left, right): Bitwise AND of left and right',
   bor = 'BOR (left, right): Bitwise OR of left and right',
   bxor = 'BXOR (left, right): Bitwise XOR of left and right',
   bshl = 'BSHL (ref, shift): Bitwise left shift of ref',
   bshr = 'BSHR (ref, shift): Bitwise logical right shift of ref',
   bsar = 'BSAR (ref, shift): Bitwise arithmetic right shift of ref',
   brol = 'BROL (ref, shift): Bitwise left rotate of ref',
   bror = 'BROR (ref, shift): Bitwise right rotate of ref',
   add = 'ADD (left, right): left + right',
   sub = 'SUB (left, right): left - right',
   mul = 'MUL (left, right): left * right',
   div = 'DIV (left, right): left / right',
   mod = 'MOD (left, right): left % right',
   pow = 'POW (left, right): left ^ right',
   neg = 'NEG (ref, kneg): -ref',
   abs = 'ABS (ref, kabs): abs(ref)',
   atan2 = 'ATAN2 (left, right): atan2(left, right)',
   ldexp = 'LDEXP (left, right): ldexp(left, right)',
   min = 'MIN (left, right): min(left, right)',
   max = 'MAX (left, right): max(left, right)',
   fpmath = 'FPMATH (ref,  fpm): fpmath(ref)',
   addov = 'ADDOV (left, right): left + right, overflow-checked',
   subov = 'SUBOV (left, right): left - right, overflow-checked',
   mulov = 'MULOV (left, right): left * right, overflow-checked',
   fpm_floor = 'FPM_FLOOR       floor(ref)',
   fpm_ceil = 'FPM_CEIL        ceil(ref)',
   fpm_trunc = 'FPM_TRUNC       trunc(ref)',
   fpm_sqrt = 'FPM_SQRT        sqrt(ref)',
   fpm_exp = 'FPM_EXP         exp(ref)',
   fpm_exp2 = 'FPM_EXP2        exp2(ref)',
   fpm_log = 'FPM_LOG         log(ref)',
   fpm_log2 = 'FPM_LOG2        log2(ref)',
   fpm_log10 = 'FPM_LOG10       log10(ref)',
   fpm_sin = 'FPM_SIN         sin(ref)',
   fpm_cos = 'FPM_COS         cos(ref)',
   fpm_tan = 'FPM_TAN         tan(ref)',
   aref = 'AREF (array, index): Array reference',
   hrefk = 'HREFK (hash, kslot): Constant hash reference',
   href = 'HREF (tab, key): Hash reference',
   newref = 'NEWREF (tab, key): Create new reference',
   urefo = 'UREFO (func, #uv): Open upvalue reference',
   urefc = 'UREFC (func, #uv): Closed upvalue reference',
   fref = 'FREF (obj, #field): Object field reference',
   strref = 'STRREF (str, index): String reference',
   aload = 'ALOAD (aref): Array load',
   hload = 'HLOAD (href): Hash load',
   uload = 'ULOAD (uref): Upvalue load',
   fload = 'FLOAD (obj, #field): Object field load',
   xload = 'XLOAD (xref, #flags): Extended load',
   sload = 'SLOAD (#slot, #flags): Stack slot load',
   vload = 'VLOAD (aref): Vararg slot load',
   astore = 'ASTORE (aref, val): Array store',
   hstore = 'HSTORE (href, val): Hash store',
   ustore = 'USTORE (uref, val): Upvalue store',
   fstore = 'FSTORE (fref, val): Object field store',
   xstore = 'XSTORE (xref, val): Extended store',
   snew = 'SNEW (data, length): Allocate interned string',
   xsnew = 'XSNEW (data, length): Allocate interned string from cdata',
   tnew = 'TNEW (#asize, #hbits): Allocate Lua table with minimum array and hash sizes',
   tdup = 'TDUP (template): Allocate Lua table, copying a template table',
   cnew = 'CNEW (ctypeid, size): Allocate mutable cdata',
   cnewi = 'CNEWI (ctypeid, val): Allocate immutable cdata',
   tbar = 'TBAR (tab): Table write barrier',
   obar = 'OBAR (obj, val): Object write barrier',
   xbar = 'XBAR: XLOAD/XSTORE optimization barrier',
   conv = 'CONV (src, #flags): Generic type conversion',
   tobit = 'TOBIT (num, bias): Convert double to integer with Lua BitOp semantics',
   tostr = 'TOSTR (number): Convert double or integer to string',
   strto = 'STRTO (str): Convert string to double',
   calln = 'CALLN (args, #ircall): Call internal function (normal)',
   calll = 'CALLL (args, #ircall): Call internal function (load)',
   calls = 'CALLS (args, #ircall): Call internal function (store)',
   callxs = 'CALLXS (args, func): Call external function (store/barrier)',
   carg = 'CARG (args, arg): Call argument extension',
   nop = 'NOP: No operation',
   base = 'BASE (#parent, #exit): BASE reference, link to parent side exit',
   pval = 'PVAL (#pref): Parent value reference',
   gcstep = 'GCSTEP: Explicit GC step',
   hiop = 'HIOP (left, right): Hold hi-word operands of split instructions',
   loop = 'LOOP: Separator before loop-part of a trace',
   use = 'USE (ref): Explicit use of a reference',
   phi = 'PHI (left, right): PHI node for loops',
   rename = 'RENAME (ref, #snap): Renamed reference below snapshot'
}

local Op = {}
IR.Op = Op

function set (se)
   local s = {}
   for _, e in ipairs(se) do s[e] = true end
   return s
end

Op.Alloc = set{ 'snew', 'xsnew', 'tnew', 'tdup', 'cnew', 'cnewi' }
Op.Arith = set{ 'add', 'sub', 'mul', 'div', 'mod', 'pow', 'neg', 'abs',
                'atan2', 'ldexp', 'min', 'max', 'fpmath', 'addov',
                'subov', 'mulov' }
Op.Barrier = set{ 'tbar', 'obar', 'xbar' }
Op.Bit = set{ 'bnot', 'bswap', 'band', 'bor', 'bxor', 'bshl', 'bshr',
              'bsar', 'brol', 'bror' }
Op.Call = set{ 'calln', 'calll', 'calls', 'callxs', 'carg' }
Op.Const = set{ 'kpri', 'kint', 'kgc', 'kptr', 'kkptr', 'knull', 'knum',
                'kint64', 'kslot' }
Op.Const64 = set{ 'kgc', 'kptr', 'kkptr', 'knum', 'kint64' }
Op.Guard = set{ 'lt', 'ge', 'le', 'gt', 'ult', 'uge', 'ule', 'ugt', 'eq',
                'ne', 'abc', 'retf' }
Op.Load = set{ 'aload', 'hload', 'uload', 'fload', 'xload', 'sload', 'vload' }
Op.Store = set{ 'astore', 'hstore', 'ustore', 'fstore', 'xstore' }
Op.Loop = set{ 'loop' }
Op.Memref = set{ 'aref', 'hrefk', 'href', 'newref', 'urefo', 'urefc',
                 'fref', 'strref' }
Op.Misc = set{ 'nop', 'base', 'pval', 'gcstep', 'hiop', 'loop', 'use',
               'phi', 'rename' }
Op.Nop = set{ 'nop' }
Op.Phi = set{ 'phi' }

function IR:new (trace, pos, prev, k)
   local ins = trace.ir[pos]
   local ret = {}

   -- 64-bit inline constants
   if prev and prev.next then
      prev.next = ret
      assert(prev.t)
      ret[prev.t] = self:const64(prev.t, ins, trace)
      prev.op1 = ret[prev.t]

   -- Opcodes
   elseif ins.o < trace.ir_max then
      ret.opcode = self:opname(trace, ins.o)
      -- Hint
      ret.hint = Opcodes[ret.opcode]
      -- Result type
      ret.t = self:typename(trace, ins.t.irt)
      -- Register and slot allocation
      ret.reg = self.reg_x64[ins.r]
      ret.slot = (ins.s > 0 and ins.s) or nil
      ret.sunk = self:isSunk(ins.r, ins.s)
      -- Operands
      if Op.Const64[ret.opcode] then
         -- 64-bit const follows
         ret.next = true
      else
         -- Parse inline operands
         local mode = trace.auditlog.ir_mode[ins.o]
         local m1 = self:modename(trace, band(mode, 3))
         local m2 = self:modename(trace, band(rshift(mode, 2), 3))
         ret.op1 = self:operand(ins, ins.op1, m1, trace, k)
         ret.op2 = self:operand(ins, ins.op2, m2, trace, k)
         -- Opcode specifics
         if self[ret.opcode] then
            self[ret.opcode](self, ret, trace)
         end
      end
   end
   return ret
end

function IR:opname (trace, opcode)
   return trace.auditlog.dwarf:enum_name(ffi.cast(trace.irop_t, opcode))
      :match("IR_(.*)"):lower()
end

function IR:modename (trace, opmode)
   return trace.auditlog.dwarf:enum_name(ffi.cast(trace.irm_t, opmode))
      :match("IRM(.*)")
end

function IR:typename (trace, typ)
   local irt = ffi.cast(trace.irt_t, band(0x1f, typ))
   local name = trace.auditlog.dwarf:enum_name(irt)
   if name then return name:match("IRT_(.*)"):lower() end
end

function IR:operand (ins, o, m, trace, k)
   if m == 'ref' then
      return self:resolve_ref(o, trace.ref_bias, k)
   elseif m == 'lit' then
      return o
   elseif m == 'cst' then
      return ins.i
   end
end

function IR:resolve_ref (ref, ref_bias, k)
   if ref > ref_bias then
      -- Reference prior IR instruction
      return ("[%d]"):format(ref-ref_bias)
   elseif k then
      -- Reference constant in k, resolve (possibly via future)
      local ik = ref_bias-ref
      if ik == 0 then
         return '<base>'
      end
      if type(k[ik].op1) ~= 'function' then
         return k[ik].op1
      else
         return k[ik].op1(k)
      end
   elseif not k then
      -- Reference constant in k, but we have no k yet:
      -- Return future reference for once we have k :-)
      return function (k) return self:resolve_ref(ref, ref_bias, k) end
   end
end

function IR:const64 (t, ins, trace)
   if t == 'num' then
      return tonumber(ins.tv.n)
   elseif t == 'intp' then
      return ins.tv.u64
   elseif t == 'str' then
      local str = assert(trace.auditlog.memory[ins.gcr])
      return trace.auditlog:lj_strdata(str)
   elseif t == 'func' then
      local func_addr = ffi.cast("uintptr_t", ins.gcr)
      local func = assert(trace.auditlog.memory[ins.gcr])
      local gcproto_t =
         assert(trace.auditlog.dwarf:find_die("GCproto")):ctype()
      local proto_addr =
         ffi.cast("uintptr_t", func.l.pc) - ffi.sizeof(gcproto_t)
      local proto = trace.auditlog.prototypes[proto_addr]
      if proto then
         return ("<func %s>"):format(proto)
      else
         return ("<func #%x>"):format(tonumber(func_addr))
      end
   else
      -- XXX - NYI
      return '<'..t..'>'
   end
end

function IR:fpmath (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:urefo (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:urefc (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:fref (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:fload (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:calln (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:calll (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:calls (ret) ret.op2 = ("#%d"):format(ret.op2) end
function IR:base (ret)
   ret.op1 = ("#%d"):format(ret.op1)
   ret.op2 = ("#%d"):format(ret.op2)
end
function IR:pval (ret) ret.op1 = ("#%d"):format(ret.op1) end
function IR:rename (ret) ret.op2 = ("#%d"):format(ret.op2) end

function IR:cnew (ret, trace)
   local desc = trace.auditlog.ctypes[ret.op1]
   if desc then
      ret.op1 = ("<ctype %s>"):format(desc)
   else
      ret.op1 = ("<ctype #%d>"):format(ret.op1)
   end
end
IR.cnewi = IR.cnew

function IR:sload (ret)
   ret.op1 = ("#%d"):format(ret.op1)
   local flags = {
      [0x01] = "parent",
      [0x02] = "frame",
      [0x04] = "typecheck",
      [0x08] = "convert",
      [0x10] = "readonly",
      [0x20] = "inherit"
   }
   ret.op2 = self:flags(ret.op2, flags)
end

function IR:xload (ret)
   local flags = {
      [0x01] = "readonly",
      [0x02] = "volatile",
      [0x04] = "unaligned"
   }
   ret.op2 = self:flags(ret.op2, flags)
end

function IR:conv (ret, trace)
   local flags = ("<flags %s→%s")
      :format(self:typename(trace, band(0x1f, ret.op2)),
              self:typename(trace, band(0x1f, rshift(ret.op2, 5))))
   if band(0x0800, ret.op2) ~= 0 then
      flags = flags.." sign-extend"
   end
   local numtoint_mode =
      ({"any", "index", "check"})[band(0xf, lshift(ret.op2, 12))]
   if numtoint_mode then
      flags = flags.." "..numtoint_mode
   end
   ret.op2 = flags..">"
end

function IR:flags (x, flags)
   local has_flags = false
   local s = "<flags"
   for mask, flag in pairs(flags) do
      if band(mask, x) ~= 0 then
         s = s.." "..flag
         has_flags = true
      end
   end
   if has_flags then
      return s..">"
   end
end

-- Logic copied from LuaJIT dump.lua
IR.isSunkReg = set{ 253, 254 }
IR.isSunkSlot = set{ 0, 255 }
function IR:isSunk (reg, slot)
   return self.isSunkReg[reg] and self.isSunkSlot[slot]
end

IR.reg_x64 = {
   "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
   "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
   "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
}

-- Module ir

return IR

