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

function snapshot(a, b)
   b = b or histogram_t()
   ffi.copy(b, a, ffi.sizeof(histogram_t))
   return b
end

function clear(histogram)
   histogram.total = 0
   for bucket = 0, bucket_count - 1 do histogram.buckets[bucket] = 0 end
end

function summarize (histogram, prev)
   local total = histogram.total
   if prev then total = total - prev.total end
   if total == 0 then return 0, 0, 0 end
   local min, max, cumulative = nil, 0, 0
   for count, lo, hi in histogram:iterate(prev) do
      if count ~= 0 then
         if not min then min = lo end
         max = hi
         cumulative = cumulative + (lo + hi) / 2 * tonumber(count)
      end
   end
   return min, cumulative / tonumber(total), max
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
   snapshot = snapshot,
   wrap_thunk = wrap_thunk,
   clear = clear,
   summarize = summarize,
   median = median,
},
__tostring = function (histogram)
   return ("min: %.2f / avg: %.2f / max: %.2f"):format(summarize(histogram))
end})

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
   self.events = self:summarize_events(self.log)
   self:compute_histogram_quantiles(self.events, 'breath_lag')
   return self
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
   local breath_tsc = nil
   local function breath_lag (entry)
      if entry.message.name == 'engine.breath_start' then
         breath_tsc = entry.tsc
      elseif breath_tsc and breath_tsc < entry.tsc then
         return entry.tsc - breath_tsc
      end
   end
   for _, entry in ipairs(log) do
      entry.lag = tsc_lag(entry)
      entry.breath_lag = breath_lag(entry)
   end
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
      for _, lag in ipairs{'lag', 'breath_lag'} do
         if entry[lag] then
            event[lag] = event[lag] or {}
            event[lag].min = math.min(event[lag].min or entry[lag], entry[lag])
            event[lag].max = math.max(event[lag].max or entry[lag], entry[lag])
            event[lag].total = (event[lag].total or 0) + entry[lag]
         end
      end
   end
   for _, event in pairs(events) do
      for _, lag in ipairs{'lag', 'breath_lag'} do
         if event[lag] then
            event[lag].histogram = new_histogram(event[lag].min/10, event[lag].max*2)
         end
      end
   end
   for _, entry in ipairs(log) do
      local event = events[entry.message.name]
      for _, lag in ipairs{'lag', 'breath_lag'} do
         if entry[lag] then
            event[lag].histogram:add(entry[lag])
         end
      end
   end
   return events
end

function Timeline:compute_histogram_quantiles (events, lag)
   for _, event in pairs(events) do
      if event[lag] then
         event[lag].q1 = event[lag].histogram:median(0.25)
         event[lag].q2 = event[lag].histogram:median(0.5)
         event[lag].q3 = event[lag].histogram:median(0.75)
      end
   end
end

function Timeline:select_events (events, filter)
   local selected = {}
   for name, event in pairs(events) do
      if name:match(filter) then
         table.insert(selected, event)
      end
   end
   return selected
end

function Timeline:sort_events_by_breath_lag (events)
   table.sort(events, function (x, y)
      local x_lag = (x.breath_lag and x.breath_lag.q2) or 0
      local y_lag = (y.breath_lag and y.breath_lag.q2) or 0
      return x_lag > y_lag
   end)
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

function Timeline:events_sorted_by_estimated_total_lag (events)
   local events_sorted = {}
   for _, event in pairs(events) do
      table.insert(events_sorted, event)
   end
   table.sort(events_sorted, function (x, y)
      return self:estimated_total_lag(x) > self:estimated_total_lag(y)
   end)
   return events_sorted
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

function Timeline:html_histogram (out, h, opt)
   out:write(("<div id='%s'></div>\n"):format(opt.id))
   out:write("<script>\n")
   out:write("var x = [\n")
   for count, lo, hi in h:iterate() do
      if count > 0 then
         out:write(("%d,"):format(math.ceil(lo)))
      end
   end
   out:write("\n]\n")
   out:write("var y = [\n")
   for count, lo, hi in h:iterate() do
      if count > 0 then
         out:write(("%f,"):format(tonumber(count)/tonumber(h.total)))
      end
   end
   out:write("\n]\n")
   out:write (([[
      var data = { x: x, y: y, type: 'bar' }
      var layout = {
         xaxis: {
            title: { text: %q },
            type: 'log',
            autorange: false,
            range: [%f, %f]
         },
         yaxis: {
            title: { text: 'density' },
            autorange: true,
            fixedrange: true
         },
         height: 300
      }
      Plotly.newPlot('%s', [data], layout);
      </script> 
   ]]):format(
      opt.unit,
      math.log10(opt.min),
      math.log10(opt.max),
      opt.id
   ))
end

function Timeline:html_breath_summary (out, events, id)
   id = 'tl_breath_lag_'..id
   out:write(("<div id='%s'></div>\n"):format(id))
   out:write("<script>\n")
   out:write("var data = [\n")
   for _, event in ipairs(events) do
      if event.breath_lag then
         out:write(("{y0:%q, q1:[%f], median:[%f], q3:[%f], type:'box', orientation:'h'},\n")
            :format(event.message.name, event.breath_lag.q1, event.breath_lag.q2, event.breath_lag.q3))
      end
   end
   out:write("]\n")
   out:write(("Plotly.newPlot(%q, data, { showlegend: false, margin: {l:200}, xaxis: { title: { text: %q } } })\n")
      :format(id, 'tsc'))
   out:write("</script>\n")
end

function Timeline:html_dump (out)
   local events = self:events_sorted_by_estimated_total_lag(self.events)
   out = out or io.stdout
   out:write("<script src='https://cdn.plot.ly/plotly-2.14.0.min.js'></script>\n")
   out:write("<h2>Breath summary</h2>\n")
   local engine_events = self:select_events(self.events, "^engine%.")
   self:sort_events_by_breath_lag(engine_events)
   self:html_breath_summary(out, engine_events, 'engine')
   out:write("<h2>App summary</h2>\n")
   local app_events = self:select_events(self.events, "^app%.")
   self:sort_events_by_breath_lag(app_events)
   self:html_breath_summary(out, app_events, 'app')
   out:write("<h2>Event lag</h2>\n")
   for _, event in ipairs(events) do
      out:write(("<h3>%s</h3>\n"):format(event.message.name))
      out:write(("<p>Estimated total count: %s</p>\n")
         :format(comma_value(round(self:estimated_total_count(event)))))
      if event.lag then
         out:write(("<p>Estimated total lag: %s tsc</p>\n")
            :format(comma_value(round(self:estimated_total_lag(event)))))
         self:html_histogram(out, event.lag.histogram, {
            id=event.message.name.."-lag",
            min=event.lag.min/2, max=event.lag.max*2,
            unit='tsc'
         })
      end
   end
end

local tl = Timeline:new("/var/run/snabb/4045267/events.timeline")
tl:html_dump()