local ffi = require("ffi")

-- RaptorJIT VMprofile reader

local VMProfile = {}

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
   assert(traceno <= self.specs.trace_max)
   assert(vmst < self.specs.vmst_max)
   return traceno*self.specs.vmst_max + vmst
end

function VMProfile:count (traceno, vmst)
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

function VMProfile:vmst_name (vmst)
   return VMProfile.vmstates[vmst]
end

function VMProfile:hot_traces ()
   local traces = {}
   for traceno=0, self.specs.trace_max do
      local trace = {
         id = traceno,
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
   local total = 0
   for traceno=0, self.specs.trace_max do
      for vmst=0, self.specs.vmst_max-1 do
         total = total + self:count(traceno, vmst)
      end
   end
   return total
end

function VMProfile:total_vmst_samples ()
   local p = {}
   for vmst=0, self.specs.vmst_max-1 do
      local vmst_name = self:vmst_name(vmst)
      for traceno=0, self.specs.trace_max do
         p[vmst_name] = (p[vmst_name] or 0) + self:count(traceno, vmst)
      end
   end
   return p
end

-- Module vmprofile
return VMProfile
