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

print("Trace 64")
local trace64 = auditlog.traces[64]
local events = auditlog:trace_events(trace64)
for _, event in ipairs(events) do
   print(event.event,
         (event.trace_abort and event.trace_abort.TraceError) or '')
end
for _, info in ipairs(auditlog:trace_contour(trace64)) do
   print(("%s%s:%d:%s:%d"):format(
         (' '):rep(info.depth),
         info.chunkname,
         info.chunkline,
         info.declname,
         info.chunkline-info.declline))
end
