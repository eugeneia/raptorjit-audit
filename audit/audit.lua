local msgpack = require("audit.msgpack")
local elf = require("audit.elf")
local dwarf = require("audit.dwarf")
local ffi = require("ffi")

-- RaptorJIT auditlog analyzer

-- auditlog:new(string) -> Auditlog
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

local Auditlog, Memory, VMProfile = {}, {}, {}
local Event, Prototype, Trace = {}, {}, {}

function Auditlog:new (path)
   local self = {
      log = nil,
      memory = Memory:new(),
      dwarf = dwarf.new(),
      events = {},
      prototypes = Memory:new(), -- new_prototype
      ctypes = {}, -- new_ctypeid
      traces = {} -- trace_stop
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
   assert(dwo, "Unable to find DARF debug info in auditlog.")
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
   local ptr_t = ffi.typeof("$ *", assert(self.dwarf:find_die(hint)):ctype())
   local ptr = ffi.cast(ptr_t, event.data)
   self.memory[assert(event.address)] = ptr
end

function Auditlog:parse_event (event)
   assert(event.type == 'event')
   event = Event:new(event, self.events[#self.events])
   self.events[#self.events+1] = event

   if event.event == 'new_prototype' then
      local proto = assert(self.memory[event.GCproto])
      event.prototype = Prototype:new{
         address = event.GCproto,
         GCproto = proto,
         chunkname = self:lj_strdata(assert(self.memory[proto.chunkname]))
      }
      self.prototypes[event.GCproto] = event.prototype

   elseif event.event == 'lex' then
      -- NOP

   elseif event.event == 'new_ctypeid' then
      event.id = self:fix_id(event.id)
      self.ctypes[event.id] = event.desc

   elseif event.event == 'trace_stop' then
      local trace = assert(self.memory[event.GCtrace])
      local jitstate = assert(self.memory[event.jit_State])
      event.trace = Trace:new{
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
      event.trace_abort = {
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
   return setmetatable(o, {__index=Event})
end

function Event:nanodelta ()
   if self.prev then
      return self.nanotime - self.prev.nanotime
   else
      return 0ULL
   end
end

function Prototype:new (o)
   local self = setmetatable(o, {__index=Prototype})
   self.lineinfo = self:colocated(self.GCproto.lineinfo, "uint32_t")
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
   return ffi.cast(
      ffi.typeof("$*", ffi.typeof(t)),
      ffi.cast("uintptr_t", self.GCproto)
      + (ffi.cast("uintptr_t", coptr) - ffi.cast("uintptr_t", self.address))
   )
end

function Prototype:firstline ()
   return self.GCproto.firstline
end

function Prototype:bcline (pos)
   return self.lineinfo[pos]
end

function Trace:new (o)
   return setmetatable(o, {__index=Trace})
end

function Auditlog:trace_events (trace)
   local start_id = self:trace_start_id(trace.GCtrace.parent,
                                        trace.GCtrace.startpc)
   local events = {}
   for _, event in ipairs(self.events) do
      -- Collect event that created this trace
      if event.event == 'trace_stop' and event.trace == trace then
         events[#events+1] = event
         -- Collect trace aborts with the same start point
      elseif event.event == 'trace_abort' then
         local jitstate = event.trace_abort.jit_State
         local abort_start_id = self:trace_start_id(jitstate.parent,
                                                    jitstate.startpc)
         if abort_start_id == start_id then
            events[#events+1] = event
         end
      end
   end
   return events
end

function Auditlog:trace_contour (trace)
   local contour = {}
   local depth
   for i=0, trace.jit_State.nbclog-1 do
      local bcrec = trace.bclog[i]
      local proto = self.prototypes[bcrec.pt]
      if proto and bcrec.framedepth ~= depth then
         depth = bcrec.framedepth
         contour[#contour+1] = {
            depth = depth,
            chunkname = proto.chunkname,
            chunkline = proto.lineinfo[bcrec.pos],
            declname = proto.declname,
            declline = proto.GCproto.firstline
         }
      end
   end
   return contour
end

-- Map memory addresses to objects
function Memory:new () return setmetatable({}, Memory) end
function Memory:__index (k) return rawget(self, Memory:key(k)) end
function Memory:__newindex (k, v) rawset(self, Memory:key(k), v) end
function Memory:key (ptr) return tostring(ffi.cast("uintptr_t", ptr)) end


-- Module audit
return Auditlog
   
