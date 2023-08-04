local ffi = require("ffi")

-- Histogram cripped from Snabb (core/histogram.lua)

local ffi = require("ffi")
local log, floor, max, min = math.log, math.floor, math.max, math.min

-- The first and last buckets are catch-alls.
local bucket_count = 200
local histogram_t = ffi.typeof([[struct {
   double minimum;
   double growth_factor_log;
   uint64_t total;
   uint64_t buckets[]]..bucket_count..[[];
}]])

local function compute_growth_factor_log(minimum, maximum)
   assert(minimum > 0)
   assert(maximum > minimum)
   -- The first and last buckets are the catch-alls; the ones in between
   -- partition the range between the minimum and the maximum.
   return log(maximum / minimum) / (bucket_count - 2)
end

function new_histogram (minimum, maximum)
   return histogram_t(minimum, compute_growth_factor_log(minimum, maximum))
end

function add(histogram, measurement)
   local bucket
   if measurement <= 0 then
      bucket = 0
   else
      bucket = log(measurement / histogram.minimum)
      bucket = bucket / histogram.growth_factor_log
      bucket = floor(bucket) + 1
      bucket = max(0, bucket)
      bucket = min(bucket_count - 1, bucket)
   end
   histogram.total = histogram.total + 1
   histogram.buckets[bucket] = histogram.buckets[bucket] + 1
end

function iterate(histogram, prev)
   local bucket = -1
   local factor = math.exp(histogram.growth_factor_log)
   local minimum = histogram.minimum
   local function next_bucket()
      bucket = bucket + 1
      if bucket >= bucket_count then return end
      local lo, hi
      if bucket == 0 then
         lo, hi = 0, minimum
      else
         lo = minimum * math.pow(factor, bucket - 1)
         hi = minimum * math.pow(factor, bucket)
         if bucket == bucket_count - 1 then hi = 1/0 end
      end
      local count = histogram.buckets[bucket]
      if prev then count = count - prev.buckets[bucket] end
      return count, lo, hi
   end
   return next_bucket
end

function median (histogram, pos)
   pos = pos or 0.5
   local point = math.floor(tonumber(histogram.total)*pos)
   local i = 0
   for count, lo, hi in histogram:iterate(prev) do
      i = i + count
      if i >= point then
         return (lo+hi)/2
      end
   end
end

ffi.metatype(histogram_t, {__index = {
   add = add,
   iterate = iterate,
   median = median
}})

-- Snabb timeline reader

local Timeline = {}

Timeline.header_t = ffi.typeof[[
   // 64B file header
   struct {
     uint64_t magic;
     uint16_t major_version;
     uint16_t minor_version;
     uint32_t log_bytes;
     uint32_t strings_bytes;
     uint8_t reserved[44];
   }
]]

Timeline.entry_t = ffi.typeof[[
   // 64B log entry
   struct {
     double tsc;       // CPU timestamp (note: assumed to be first elem below)
     uint16_t msgid;     // msgid*16 is index into string table
     uint16_t core_numa; // TSC_AUX: core (bits 0-7) + numa (12-15)
     uint32_t reserved;  // (available for future use)
     double arg0, arg1, arg2, arg3, arg4, arg5; // message arguments
   }
]]

Timeline.magic = 0xa3ff7223441d0001ULL
Timeline.version = { major=3, minor=0}

function Timeline:new (path)
   local self = setmetatable({}, {__index=Timeline})
   -- Read profile
   local f = io.open(path, "r")
   assert(f, "Unable to open file: "..path)
   self.blob = assert(f:read("*a"))
   self.size = #self.blob
   self.timeline = ffi.cast("uint8_t*", self.blob)
   assert(f:close())
   self.header = ffi.cast(ffi.typeof("$*", self.header_t), self.timeline)
   assert(self.header.magic == self.magic)
   assert(self.header.major_version == self.version.major)
   assert(self.header.minor_version == self.version.minor)
   local strings = self:read_strings(self.timeline + 64 + self.header.log_bytes)
   self.messages = {}
   for id, string in pairs(strings) do
      self.messages[id] = self:parse_message(string)
   end
   self.log = self:read_log(self.timeline + 64)
   self:compute_lag(self.log)
   self.tsc_freq = self:compute_tsc_freq(self.log)
   self.event_period = self:compute_event_period(self.log)
   self.tsc_ns = 1e9 / self.tsc_freq
   self.events = self:summarize_events(self.log)
   self.sleep = self:summarize_sleep(self.log)
   return self
end

function Timeline:toCSV (out)
   local args = {}
   for _, message in pairs(self.messages) do
      for _, arg in ipairs(message.args) do
         args[arg] = true
      end
   end
   out:write("tsc,lag,core,node,message,level,rate")
   for arg in pairs(args) do
      out:write((",%s"):format(arg))
   end
   out:write("\n")
   for _, entry in ipairs(self.log) do
      out:write(("%d,%d,%d,%d,%q,%d,%d")
         :format(
            entry.tsc,
            entry.lag or 0,
            entry.core,
            entry.node,
            entry.message.name,
            entry.message.level,
            entry.message.rate))
      for arg in pairs(args) do
         out:write((",%s"):format(entry.args[arg] or ''))
      end
      out:write("\n")
   end
end

function Timeline:read_strings (strings)
   local tab = {}
   local offset = 0
   while offset < self.header.strings_bytes do
      local id = offset / 16
      local string = ffi.string(strings+offset)
      if #string > 0 then
         tab[id] = string
         offset = offset + math.ceil((#string+1)/16)*16
      else break end
   end
   return tab
end

function Timeline:parse_message (string)
   local level, rate, name, param, summary =
      string:match("^(%d+),(%d+)|([^:]+):([^\n]*)\n(.*)$")
   local args = {}
   for arg in param:gmatch("[^%s]+") do
      table.insert(args, arg)
   end
   return {
      level = tonumber(level),
      rate = tonumber(rate),
      name = name,
      args = args,
      summary = summary
   }
end

function Timeline:read_log (entries)
   local entries = ffi.cast(ffi.typeof("$*", self.entry_t), entries)
   local log = {}
   for i=0, (self.header.log_bytes/64)-1 do
      local entry = entries[i]
      if entry.tsc > 0 then
         local message = assert(self.messages[entry.msgid])
         local e = {
            tsc = entry.tsc,
            core = bit.band(entry.core_numa, 0x7f),
            node = bit.rshift(entry.core_numa, 7),
            message = message,
            args = {}
         }
         for n, arg in ipairs(message.args) do
            e.args[arg] = entry['arg'..(n-1)]
         end
         table.insert(log, e)
      else break end
   end
   return log
end

function Timeline:compute_lag (log)
   -- FIXME: account for unsynchronized TSC across core/node
   local prev_tsc = {}
   local function tsc_lag (entry)
      local prev = prev_tsc[entry.message.level]
      for level = entry.message.level, 9 do
         prev_tsc[level] = entry.tsc
      end
      if prev and prev < entry.tsc then
         return entry.tsc - prev
      end
   end
   for _, entry in ipairs(log) do
      entry.lag = tsc_lag(entry)
   end
end

function Timeline:compute_tsc_freq (log)
   local start, stop
   for _, entry in ipairs(log) do
      if entry.message.name == 'engine.got_monotonic_time' then
         if not start then
            start = entry
         else
            stop = entry
            if start.tsc < stop.tsc then
               break
            else
               start = stop
               stop = nil
            end
         end
      end
   end
   if start and stop then
      local ticks = stop.tsc - start.tsc
      local ns = tonumber(stop.args.unixnanos - start.args.unixnanos)
      return ticks / ns * 1e9
   else
      return 1/0
   end
end

function Timeline:compute_event_period (log)
   local period = 0
   local start, stop
   for _, entry in ipairs(log) do
      if entry.message.name == 'engine.got_monotonic_time' then
         if not start then
            start = entry
         else
            stop = entry
            if start.tsc < stop.tsc then
               period = period + tonumber(stop.args.unixnanos - start.args.unixnanos)/1e9
            end
            start, stop = stop, nil
         end
      end
   end
   return period
end

function Timeline:summarize_events (log)
   local events = {}
   for _, entry in ipairs(log) do
      if not events[entry.message.name] then
         local event = {
            message = entry.message,
            count = 0,
            core = {},
            node = {}
         }
         events[entry.message.name] = event
      end
      local event = events[entry.message.name]
      event.count = event.count + 1
      event.core[entry.core] = (event.core[entry.core] or 0) + 1
      event.core[entry.node] = (event.core[entry.node] or 0) + 1
      if entry.lag then
         event.lag = event.lag or {}
         event.lag.min = math.min(event.lag.min or entry.lag, entry.lag)
         event.lag.max = math.max(event.lag.max or entry.lag, entry.lag)
         event.lag.avg = ((event.lag.avg or entry.lag) + entry.lag)/2
         event.lag.total = (event.lag.total or 0) + entry.lag
      end
   end
   for _, event in pairs(events) do
      if event.lag then
         event.lag.histogram = new_histogram(event.lag.min/10, event.lag.max*2)
      end
   end
   for _, entry in ipairs(log) do
      local event = events[entry.message.name]
      if entry.lag then
         event.lag.histogram:add(entry.lag)
      end
   end
   for _, event in pairs(events) do
      if event.lag then
         event.lag.q1 = event.lag.histogram:median(0.25)
         event.lag.q2 = event.lag.histogram:median(0.5)
         event.lag.q3 = event.lag.histogram:median(0.75)
      end
   end
   return events
end

function Timeline:summarize_sleep (log)
   local sleep = {
      min = 1, max = 1000,
      histogram = new_histogram(0.1, 1000)
   }
   for _, entry in ipairs(log) do
      if entry.message.name == 'engine.sleep_on_idle' or 
         entry.message.name == 'engine.sleep_Hz'
      then
         sleep.histogram:add(entry.args.usec)
      end
   end
   return sleep
end

function Timeline:select_events (events, patterns)
   patterns = patterns or {''}
   local selected = {}
   for name, event in pairs(events) do
      for _, pattern in ipairs(patterns) do
         if name:match(pattern) then
            table.insert(selected, event)
            break
         end
      end
   end
   return selected
end

function Timeline:sort_events_by_median_lag ()
   return function (x, y)
      local x_avg = (x.lag and x.lag.q2) or 0
      local y_avg = (y.lag and y.lag.q2) or 0
      return x_avg < y_avg
   end
end

function Timeline:sort_events_by_name ()
   return function (x, y)
      return x.message.name < y.message.name
   end
end

function Timeline:rate_factor (event)
   return 5^(9-event.message.rate)
end

function Timeline:estimated_total_lag (event)
   if event.lag then
      return event.lag.total * self:rate_factor(event)
   else
      return 0
   end
end

function Timeline:estimated_total_count (event)
   return event.count * self:rate_factor(event)
end

function comma_value(n) -- credit http://richard.warburton.it
   if type(n) == 'cdata' then
      n = string.match(tostring(n), '^-?([0-9]+)U?LL$') or tonumber(n)
   end
   if n ~= n then return "NaN" end
   local left,num,right = string.match(n,'^([^%d]*%d)(%d*)(.-)$')
   return left..(num:reverse():gsub('(%d%d%d)','%1,'):reverse())..right
end

function round (n)
   local f = 10^math.floor(math.log(n, 10))
   return math.floor(n/f)*f
end

return Timeline
