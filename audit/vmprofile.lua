local ffi = require("ffi")

-- RaptorJIT VMprofile reader

-- vmprofile:new(string, DWARF) -> VMProfile
--    Read VMProfile from path using DWARF debug info.
--
-- VMProfile:delta(VMProfile) -> VMProfile
--    Make a new VMProfile that is the delta of two profiles. a:delta(b) -> b-a
--
-- VMProfile:count(traceno, vmst) -> number
--    Sample count for Trace by traceno in VM state.
--
-- VMProfile:hot_traces() -> array
--    Return traces and their sample counts sorted by total samples.
--
-- VMProfile:total_samples() -> number
--    Total number of samples counted in VMProfile.
--
-- VMProfile:total_vmst_samples() -> table
--    Total number of samples for each VM state.
--
-- VMProfile:dump(string)
--    Dump VMProfile to file at path.

local VMProfile = {}

VMProfile.vmstates = {
   [0] = "interp",
   [1] = "c",
   [2] = "igc",
   [3] = "exit",
   [4] = "record",
   [5] = "opt",
   [6] = "asm",
   [7] = "head",
   [8] = "loop",
   [9] = "jgc",
   [10] = "ffi"
}

local vmprofile_t = ffi.typeof[[struct {
   uint32_t magic;               /* 0x1d50f007 */
   uint16_t major, minor;        /* 4, 0 */
   uint64_t count[1];
}]]
local vmprofile_ptr_t = ffi.typeof("$ *", vmprofile_t)

function VMProfile:new (path, dwarf)
   local self = setmetatable({}, {__index=VMProfile})
   local trace_max = dwarf:find_die('LJ_VMPROFILE_TRACE_MAX')
   local vmst_max = dwarf:find_die("LJ_VMST__MAX")
   self.specs = {
      trace_max = (trace_max and trace_max:attributes().const_value) or 4096,
      vmst_max = assert(vmst_max):attributes().const_value
   }
   -- Read profile
   local f = io.open(path, "r")
   assert(f, "Unable to open file: "..path)
   self.blob = assert(f:read("a*"))
   self.profile = ffi.cast(vmprofile_ptr_t, self.blob)
   assert(self.profile.magic == 0x1d50f007,
          "VMProfile has wrong magic number: "..path)
   assert(self.profile.major == 4 and self.profile.minor >= 0,
          "VMProfile has unsupported format version: "..path)

   return self
end

function VMProfile:index (traceno, vmst)
   traceno = traceno or 0
   assert(traceno <= self.specs.trace_max)
   assert(vmst < self.specs.vmst_max)
   return traceno*self.specs.vmst_max + vmst
end

function VMProfile:count (traceno, vmst)
   traceno = traceno or 0
   return tonumber(self.profile.count[self:index(traceno, vmst)])
end

function VMProfile:delta (vmprofile)
   -- Clone profile
   for spec, value in pairs(self.specs) do
      assert(vmprofile.specs[spec] == value, "VMProfile spec mismatch: "..spec)
   end
   local delta = setmetatable({specs=self.specs}, {__index=VMProfile})
   delta.blob = ffi.new("uint8_t[?]", #self.blob)
   delta.profile = ffi.cast(vmprofile_ptr_t, delta.blob)
   delta.profile.magic, delta.profile.major, delta.profile.minor =
      self.profile.magic, self.profile.major, self.profile.minor
   -- Populate with count deltas
   for traceno=0, self.specs.trace_max do
      for vmst=0, self.specs.vmst_max-1 do
         local idx = self:index(traceno, vmst)
         delta.profile.count[idx] =
            vmprofile.profile.count[idx] - self.profile.count[idx]
      end
   end

   return delta
end

function VMProfile:vmst_name (vmst)
   return VMProfile.vmstates[vmst]
end

function VMProfile:hot_traces ()
   self._hot_traces = self._hot_traces or self:hot_traces1()
   return self._hot_traces
end
function VMProfile:hot_traces1 ()
   local traces = {}
   for traceno=0, self.specs.trace_max do
      local trace = {
         traceno = (traceno > 0) and traceno or nil,
         vmst = {},
         total = 0
      }
      for vmst=0, self.specs.vmst_max-1 do
         local count = self:count(traceno, vmst)
         trace.vmst[self:vmst_name(vmst)] = count
         trace.total = trace.total + count
      end
      if trace.total > 0 then
         --print(traceno, trace.total)
         traces[#traces+1] = trace
      end
   end
   table.sort(traces, function (x, y) return x.total > y.total end)
   return traces
end

function VMProfile:total_samples ()
   self._total_samples = self._total_samples or self:total_samples1()
   return self._total_samples
end

function VMProfile:total_samples1 ()
   local total = 0
   for traceno=0, self.specs.trace_max do
      for vmst=0, self.specs.vmst_max-1 do
         total = total + self:count(traceno, vmst)
      end
   end
   return total
end

function VMProfile:total_vmst_samples ()
   self._total_vmst_samples = self._total_vmst_samples
                           or self:total_vmst_samples1()
   return self._total_vmst_samples
end
function VMProfile:total_vmst_samples1 ()
   local p = {}
   for vmst=0, self.specs.vmst_max-1 do
      local vmst_name = self:vmst_name(vmst)
      for traceno=0, self.specs.trace_max do
         p[vmst_name] = (p[vmst_name] or 0) + self:count(traceno, vmst)
      end
   end
   return p
end

function VMProfile:dump (path)
   local f = assert(io.open(path, "w"))
   assert(f:write(self.blob))
   assert(f:close())
end

-- Module vmprofile
return VMProfile
