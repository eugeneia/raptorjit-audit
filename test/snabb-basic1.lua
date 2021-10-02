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

local trace21 = assert(auditlog.traces[21])
print()
print(trace21)
print("parent")
print("", trace21:parent() or "none, this is a root trace")
print("children")
for _, child in ipairs(trace21:children()) do
   print("", child)
end
for _, info in ipairs(trace21:contour()) do
   print(("%s%s:%d:%s:%d"):format(
         (' '):rep(info.framedepth),
         info.chunkname,
         info.chunkline,
         info.declname,
         info.chunkline-info.declline))
end
for _, bc in ipairs(trace21:bytecodes()) do
   print(bc.name, '', bc.a, bc.b, bc.c, bc.d, bc.j)
end

local trace25 = auditlog.traces[25]
print()
print(trace25)
for _, event in ipairs(trace25:events()) do
   print(("%.3fs"):format(event:reltime()), event)
end
for _, info in ipairs(trace25:contour()) do
   print(("%s%s:%d:%s:%d"):format(
         (' '):rep(info.framedepth),
         info.chunkname,
         info.chunkline,
         info.declname,
         info.chunkline-info.declline))
end
local insn = trace25:instructions()
for i, ins in ipairs(insn) do
   print(i, ins.sunk and '>' or '', ins.reg or ins.slot or '', ins.t or '',
         ins.opcode, ins.op1 or '', ins.op2 or '') -- , ins.hint)
end

auditlog:add_profile("test/snabb-basic1/vmprofile/apps.basic.basic_apps.vmprofile")
for name, profile in pairs(auditlog:select_profiles()) do
   print()
   print(name, "total samples: "..profile:total_samples())
   local vmst_samples = profile:total_vmst_samples()
   for _, vmst in pairs(profile.vmstates) do
      print("", vmst, vmst_samples[vmst])
   end

   local hot_traces = profile:hot_traces()
   for i=1,3 do
      print()
      print("Trace", hot_traces[i].traceno or '<notrace>')
      print("total samples", hot_traces[i].total)
      for _, vmst in pairs(profile.vmstates) do
         print("", vmst, hot_traces[i].vmst[vmst])
      end
   end
end
