local audit = require("audit")

local auditlog = audit:new("test/snabb-basic1/audit.log")

print("nevents", #auditlog.events)
local ntraces, nprototypes, nctypes = 0, 0, 0
for _ in pairs(auditlog.traces) do ntraces = ntraces + 1 end
for _ in pairs(auditlog.prototypes) do nprototypes = nprototypes + 1 end
for _ in pairs(auditlog.ctypes) do nctypes = nctypes + 1 end
print("ntraces", ntraces)
print("nproto", nprototypes)
print("nctypes", nctypes)

print()
print("Trace 21")
local trace21 = assert(auditlog.traces[21])
for _, info in ipairs(auditlog:trace_contour(trace21)) do
   print(("%s%s:%d:%s:%d"):format(
         (' '):rep(info.depth),
         info.chunkname,
         info.chunkline,
         info.declname,
         info.chunkline-info.declline))
end

print()
print("Trace 25")
local trace25 = auditlog.traces[25]
local events = auditlog:trace_events(trace25)
for _, event in ipairs(events) do
   print(event.event,
         (event.trace_abort and event.trace_abort.TraceError) or '')
end
for _, info in ipairs(auditlog:trace_contour(trace25)) do
   print(("%s%s:%d:%s:%d"):format(
         (' '):rep(info.depth),
         info.chunkname,
         info.chunkline,
         info.declname,
         info.chunkline-info.declline))
end

local vmprofile = require("audit.vmprofile")

local profile_name = "apps.basic.basic_apps"
local profile = vmprofile:new(
   "test/snabb-basic1/vmprofile/"..profile_name..".vmprofile",
   auditlog.dwarf
)
print()
print(profile_name, "total samples: "..profile:total_samples())
local vmst_samples = profile:total_vmst_samples()
for _, vmst in pairs(vmprofile.vmstates) do
   print(vmst, vmst_samples[vmst])
end

local hot_traces = profile:hot_traces()
for i=1,3 do
   print()
   print("Trace", hot_traces[i].id)
   print("total samples", hot_traces[i].total)
   for _, vmst in pairs(vmprofile.vmstates) do
      print("", vmst, hot_traces[i].vmst[vmst])
   end
end
