local msgpack = require("audit.msgpack")
local elf = require("audit.elf")
local dwarf = require("audit.dwarf")
local vmprofile = require("audit.vmprofile")
local bytecode = require("audit.bytecode")
local ir = require("audit.ir")
local ffi = require("ffi")

-- RaptorJIT auditlog analyzer

-- audit:new(string) -> Auditlog
--    Load Auditlog at path.
--
-- Auditlog.events -> array[Event]
-- Auditlog.traces -> table[traceid]=Trace
--
-- Auditlog:trace_events(Trace) -> array[Event]
--    Find events related to trace (trace_stop, trace_abort).
--
-- Auditlog:trace_contour(Trace) -> contour
--    Return contour for Trace.
--
-- Auditlog:add_profile(string, number|nil)
--   Load VMProfile at path and add it to AuditLog.
--   The second argument is a timestamp that defaults to os.time().

local Auditlog, Memory, VMProfile = {}, {}, {}
local Event, Prototype, Trace, TraceAbort = {}, {}, {}, {}

function Auditlog:new (path)
   local self = {
      log = nil,
      memory = Memory:new(),
      dwarf = dwarf.new(),
      ir_mode = nil,
      events = {},
      prototypes = Memory:new(), -- new_prototype
      ctypes = {}, -- new_ctypeid
      traces = {}, -- trace_stop
      profiles = {},
   }
   self = setmetatable(self, {__index=Auditlog})
   -- Read auditlog
   local f = io.open(path, "r")
   assert(f, "Unable to open file: "..path)
   local data = assert(f:read("a*"))
   self.log = self:read_auditlog(data)
   -- Find DWARF debug info
   local dwo
   for _, entry in ipairs(self.log) do
      if entry.type == 'blob' and entry.name == 'lj_dwarf.dwo' then
         dwo = entry
         break
      end
   end
   assert(dwo, "Unable to find DWARF debug info in auditlog.")
   -- Parse debug information entries (DIE)
   for name, section in elf.new(dwo.data):sections() do
      self.dwarf:add_section(name, section)
   end
   self.dwarf:load()
   -- Parse auditlog events
   for _, entry in ipairs(self.log) do
      -- Load memory logged in auditlog into map memory[address]=obj
      if entry.type == 'memory' then
         self:parse_memory(entry)
         -- Load lj_ir_mode
         if entry.hint == 'lj_ir_mode' then
            self.ir_mode = self.memory[entry.address]
         end
      end
      -- Parse event
      if entry.type == 'event' then
         self:parse_event(entry)
      end
   end
   return self
end

function Auditlog:read_auditlog (data)
   local len, offset = #data, 0
   data = ffi.cast("uint8_t *", data)
   local log = {}
   while offset < len do
      local event, elen = msgpack.read(data, offset)
      offset = offset + elen
      log[#log+1] = event
   end
   return log
end

function Auditlog:parse_memory (event)
   assert(event.type == 'memory')
   local hint = event.hint:match("[a-zA-Z0-9_]+")
   local die = assert(self.dwarf:find_die(hint))
   -- XXX - tricky to decide whether to make a pointer to ctype or
   --       if ctype is already a pointer type!
   local ptr_t
   if die.tag == 'variable' then
      ptr_t = die:ctype()
   else
      ptr_t = ffi.typeof("$ *", die:ctype())
   end
   local ptr = ffi.cast(ptr_t, event.data)
   self.memory[assert(event.address)] = ptr
end

function Auditlog:parse_event (event)
   assert(event.type == 'event')
   if event.event == 'new_ctypeid' and event.id then
      -- Rename ctype id field
      event.ctype = event.id
   end
   event.id = #self.events+1
   event = Event:new(event, self.events[#self.events])
   self.events[event.id] = event

   if event.event == 'new_prototype' then
      local proto = assert(self.memory[event.GCproto])
      event.prototype = Prototype:new{
         auditlog = self,
         address = event.GCproto,
         GCproto = proto,
         chunkname = self:lj_strdata(assert(self.memory[proto.chunkname]))
      }
      self.prototypes[event.GCproto] = event.prototype

   elseif event.event == 'lex' then
      -- NOP

   elseif event.event == 'new_ctypeid' then
      event.ctype = self:fix_id(event.ctype)
      self.ctypes[event.ctype] = event.desc

   elseif event.event == 'trace_stop' then
      local trace = assert(self.memory[event.GCtrace])
      local jitstate = assert(self.memory[event.jit_State])
      event.trace = Trace:new{
         auditlog = self,
         GCtrace = trace,
         mcode = assert(self.memory[trace.mcode]),
         snap = assert(self.memory[trace.snap]),
         snapmap = assert(self.memory[trace.snapmap]),
         ir = assert(self.memory[trace.ir+trace.nk]),
         szirmcode = assert(self.memory[trace.szirmcode]),
         traceno = self:fix_id(trace.traceno),
         jit_State = jitstate,
         bclog = assert(self.memory[jitstate.bclog])
      }
      self.traces[trace.traceno] = event.trace
      
   elseif event.event == 'trace_abort' then
      local TraceError_t = self.dwarf:find_die("TraceError"):ctype()
      local trace_error = ffi.cast(TraceError_t, event.TraceError)
      local jitstate = assert(self.memory[event.jit_State])
      local bclog = assert(self.memory[jitstate.bclog])
      event.trace_abort = TraceAbort:new{
         auditlog = self,
         TraceError = self.dwarf:enum_name(trace_error),
         jit_State = jitstate,
         bclog = bclog
      }

   end
end

function Auditlog:lj_strdata (gcstr)
   return ffi.string(ffi.cast("char *", gcstr+1), gcstr.len)
end

function Auditlog:fix_id (id)
   -- Normalize id to number, ensure its not truncated
   local id_n = tonumber(id)
   return assert(id == id_n and id_n)
end

function Auditlog:trace_start_id (parent, startpc)
   return ("%d/%s"):format(
      parent, bit.tohex(ffi.cast("uintptr_t", startpc))
   )
end

function Event:new (o, prev)
   o.prev = prev
   return setmetatable(o, {__index=Event, __tostring=Event.__tostring})
end

function Event:nanodelta ()
   self._nanodelta = self._nanodelta or self:nanodelta1()
   return self._nanodelta
end
function Event:nanodelta1 ()
   if self.prev then
      return self.nanotime - self.prev.nanotime
   else
      return 0ULL
   end
end

function Event:reltime ()
   self._reltime = self._reltime or self:reltime1()
   return self._reltime
end
function Event:reltime1 ()
   local event = self
   local time = 0
   while event.prev do
      time = time + tonumber(event:nanodelta())/1e9
      event = event.prev
   end
   return time
end

function Event:__tostring ()
   local details = ''
   if self.event == 'new_prototype' then
      details = self.prototype
   elseif self.event == 'new_ctypeid' then
      details = ("%d %s"):format(self.id, self.desc)
   elseif self.event == 'trace_stop' then
      details = self.trace
   elseif self.event == 'trace_abort' then
      details = self.trace_abort
   end
   return ("Event %s (%s)"):format(self.event, details)
end

function Prototype:new (o)
   local self = setmetatable(o, {__index=Prototype,
                                 __tostring=Prototype.__tostring})
   self.bcins_t = assert(self.auditlog.dwarf:find_die("BCIns")):ctype()
   self.bcline_t = assert(self.auditlog.dwarf:find_die("BCLine")):ctype()
   self.bcop_t = assert(self.auditlog.dwarf:find_die("BCOp")):ctype()
   self.bytecodes =
      self:colocated(self.address+ffi.sizeof(self.GCproto[0]), self.bcins_t)
   if self.GCproto.lineinfo ~= nil then
      self.lineinfo = self:colocated(self.GCproto.lineinfo, self.bcline_t)
   else
      self.lineinfo = nil
   end
   if self.GCproto.declname ~= nil then
      self.declname = ffi.string(self:colocated(self.GCproto.declname, "char"))
   else
      self.declname = "?"
   end
   return self
end

function Prototype:colocated (coptr, t)
   assert(self.address ~= nil)
   assert(self.GCproto ~= nil)
   assert(coptr ~= nil)
   return ffi.cast(
      ffi.typeof("$*", ffi.typeof(t)),
      ffi.cast("uintptr_t", self.GCproto)
      + (ffi.cast("uintptr_t", coptr) - ffi.cast("uintptr_t", self.address))
   )
end

function Prototype:bc (pos)
   return bytecode:from_prototype(self, pos)
end

function Prototype:bcline (pos)
   return self.lineinfo and self.lineinfo[pos]
end

function Prototype:__tostring ()
   return ("%s:%d:%s"):format(self.chunkname,
                              self.GCproto.firstline,
                              self.declname)
end

function Trace:new (o)
   local self = setmetatable(o, {__index=Trace, __tostring=Trace.__tostring})
   self.irop_t = assert(self.auditlog.dwarf:find_die("IROp")):ctype()
   local ir_max = assert(self.auditlog.dwarf:find_die("IR__MAX"))
   self.ir_max = ir_max:attributes().const_value
   self.irm_t = assert(self.auditlog.dwarf:find_die("IRMode")):ctype()
   self.irt_t = assert(self.auditlog.dwarf:find_die("IRType")):ctype()
   local ref_bias = assert(self.auditlog.dwarf:find_die("REF_BIAS"))
   self.ref_bias = ref_bias:attributes().const_value
   return self
end

function Trace:parent ()
   local parent = self.auditlog:fix_id(self.GCtrace.parent)
   if parent ~= 0 then
      return assert(self.auditlog.traces[parent])
   end
end

function Trace:children ()
   self._children = self._children or self:children1()
   return self._children
end
function Trace:children1 ()
   local children = {}
   for _, trace in pairs(self.auditlog.traces) do
      if trace:parent() == self then
         children[#children+1] = trace
      end
   end
   return children
end

function Trace:start_id ()
   return self.auditlog:trace_start_id(self.GCtrace.parent,
                                       self.GCtrace.startpc)
end

function Trace:events ()
   local start_id = self:start_id()
   local events = {}
   for _, event in ipairs(self.auditlog.events) do
      -- Collect event that created this trace
      if event.event == 'trace_stop' and event.trace == self then
         events[#events+1] = event
         -- Collect trace aborts with the same start point
      elseif event.event == 'trace_abort' then
         local abort_start_id = event.trace_abort:start_id()
         if abort_start_id == start_id then
            events[#events+1] = event
         end
      end
   end
   return events
end

function Trace:instructions ()
   local nk = self.ref_bias - self.GCtrace.nk
   local k = {}
   -- Collect constants
   for i = 0, nk-1 do
      k[nk-i] = ir:new(self, i, k[nk-i+1])
   end
   -- Parse IR instructions
   local nins = self.GCtrace.nins - self.ref_bias - 1
   local ret = {}
   for i = 1, nins-1 do
      ret[#ret+1] = ir:new(self, nk+i, ret[#ret], k)
   end
   return ret
end

function Trace:__tostring ()
   local lineinfo = self:lineinfo(0)
   return ("Trace %d from %s:%d:%s")
      :format(self.traceno,
              lineinfo.chunkname,
              lineinfo.chunkline,
              lineinfo.declname)
end

function Trace:lineinfo (bcpos)
   bcpos = bcpos or 0
   local bcrec = self.bclog[bcpos]
   local proto = self.auditlog.prototypes[bcrec.pt]
   return {
      framedepth = bcrec.framedepth,
      chunkname = (proto and proto.chunkname) or '?',
      chunkline = (proto and proto:bcline(bcrec.pos)) or 0,
      declname = (proto and proto.declname) or '?',
      declline = (proto and proto.GCproto.firstline) or 0
   }
end

function Trace:contour ()
   local contour = {}
   local depth
   for bcpos=0, self.jit_State.nbclog-1 do
      local lineinfo = self:lineinfo(bcpos)
      if lineinfo.framedepth ~= depth and lineinfo.declname ~= '?' then
         depth = lineinfo.framedepth
         contour[#contour+1] = lineinfo
      end
   end
   return contour
end

function Trace:bytecodes ()
   local bytecodes = {}
   for bcpos=0, self.jit_State.nbclog-1 do
      local bcrec = self.bclog[bcpos]
      local proto = self.auditlog.prototypes[bcrec.pt]
      if proto then
         bytecodes[#bytecodes+1] = proto:bc(bcrec.pos)
      else
         bytecodes[#bytecodes+1] = {}
      end
   end
   return bytecodes
end

function TraceAbort:new (o)
   return setmetatable(o, {__index=TraceAbort,
                           __tostring=TraceAbort.__tostring})
end

function TraceAbort:start_id ()
   return self.auditlog:trace_start_id(self.jit_State.parent,
                                       self.jit_State.startpc)
end

TraceAbort.lineinfo = Trace.lineinfo
TraceAbort.contour = Trace.contour
TraceAbort.bytecodes = Trace.bytecodes

function TraceAbort:__tostring ()
   local bcrec_0 = self.bclog[0]
   local proto_0 = self.auditlog.prototypes[bcrec_0.pt]
   local chunkname_0 = (proto_0 and proto_0.chunkname) or '?'
   local chunkline_0 = (proto_0 and proto_0:bcline(bcrec_0.pos)) or 0
   local declname_0 = (proto_0 and proto_0.declname) or '?'
   local bcrec_err = self.bclog[self.jit_State.nbclog-1]
   local proto_err = self.auditlog.prototypes[bcrec_err.pt]
   local chunkname_err = (proto_err and proto_err.chunkname) or '?'
   local chunkline_err = (proto_err and proto_err:bcline(bcrec_err.pos)) or 0
   return ("%s at %s:%d during trace from %s:%d:%s")
      :format(self.TraceError,
              chunkname_err, chunkline_err,
              chunkname_0, chunkline_0, declname_0)
end

function Auditlog:add_profile (path, timestamp)
   local profile = vmprofile:new(path, self.dwarf)
   local name = path:match("([^/]+)%.vmprofile")
   local snapshots = self.profiles[name]
   local snapshot = {
      timestamp = timestamp or os.time(),
      profile = profile
   }
   if snapshots then
      assert(snapshots[#snapshots].timestamp <= snapshot.timestamp,
             "Auditlog already has a later profile for: "..name)
      snapshots[#snapshots+1] = snapshot
   else
      self.profiles[name] = {snapshot}
   end
end

function Auditlog:select_profiles (starttime, endtime)
   if not endtime then
      endtime = os.time()
   elseif endttime < 0 then
      endtime = endtime + os.time()
   end
   if not starttime then
      starttime = 0
   elseif starttime < 0 then
      starttime = starttime + endtime
   end
   local profiles = {}
   for name, snapshots in pairs(self.profiles) do
      local first, last
      for _, snapshot in ipairs(snapshots) do
         if not first or snapshot.timestamp <= starttime then
            first = snapshot.profile
         end
         if not last or snapshot.timestamp <= endtime then
            last = snapshot.profile
         end
         if snapshot.timestamp >= endtime then
            break
         end
      end
      if first and last and first ~= last then
         profiles[name] = first:delta(last)
      else
         profiles[name] = last or first
      end
   end
   return profiles
end

-- Map memory addresses to objects
function Memory:new () return setmetatable({}, Memory) end
function Memory:__index (k) return rawget(self, Memory:key(k)) end
function Memory:__newindex (k, v) rawset(self, Memory:key(k), v) end
function Memory:key (ptr) return tostring(ffi.cast("uintptr_t", ptr)) end


-- Module audit
return Auditlog
   
