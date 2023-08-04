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

function Timeline:html_histogram (out, lag, xlabel, id)
   out:write(("<div id='%s'></div>\n"):format(id))
   out:write("<script>\n")
   out:write("var x = [\n")
   for count, lo, hi in lag.histogram:iterate() do
      if count > 0 then
         out:write(("%d,"):format(math.ceil(lo)))
      end
   end
   out:write("\n]\n")
   out:write("var y = [\n")
   for count, lo, hi in lag.histogram:iterate() do
      if count > 0 then
         local density = tonumber(count) / tonumber(lag.histogram.total)
         out:write(("%f,"):format(density))
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
         height: 300, width: 800
      }
      Plotly.newPlot('%s', [data], layout);
      </script> 
   ]]):format(
      xlabel,
      math.log10(lag.min),
      math.log10(lag.max),
      id
   ))
end

function Timeline:html_boxplot (out, events, xlabel, id)
   out:write(("<div id='%s'></div>\n"):format(id))
   out:write("<script>\n")
   out:write("var data = [\n")
   for _, event in ipairs(events) do
      if event.lag then
         out:write(("{y0:%q, q1:[%f], median:[%f], q3:[%f], type:'box', orientation:'h', hoverinfo:'x'},\n")
            :format(
               event.message.name,
               event.lag.q1, event.lag.q2, event.lag.q3
            ))
      end
   end
   out:write("]\n")
   out:write(([[Plotly.newPlot(%q, data, {
         showlegend: false,
         margin: {l:200},
         height: 600, width: 800,
         xaxis: {title: {text: %q}},
         yaxis: {fixedrange:true}
      })]]):format(id, xlabel))
   out:write("\n</script>\n")
end

function Timeline:html_report_timeline (out)
   out = out or io.stdout
   out:write("<details>\n")
   out:write("<summary>Timeline</summary>\n")
   out:write("<script src='https://cdn.plot.ly/plotly-2.14.0.min.js'></script>\n")

   out:write("<details open>\n")
   out:write("<summary>Landmarks</summary>\n")
   out:write("<table>\n")
   out:write("<tbody>\n")
   out:write("<tr>\n")
   out:write("<td><b>tsc</b> frequency is</td>\n")
   out:write(("<td class=right>%.2f Ghz</td>\n"):format(self.tsc_freq/1e9))
   out:write("</tr>\n")
   out:write("<tr>\n")
   out:write("<td>One <b>tsc</b> tick is</td>\n")
   out:write(("<td class=right>%.2f ns</td>\n"):format(self.tsc_ns))
   out:write("</tr>\n")
   out:write("<tr>\n")
   out:write("<td>Events span a period of</td>\n")
   out:write(("<td class=right>%.2f s</td>\n"):format(self.event_period))
   out:write("</tr>\n")
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</details>\n")

   out:write("<details>\n")
   out:write("<summary>Engine summary</summary>\n")
   local engine_events = self:select_events(self.events, {
      '^engine%.got_monotonic_time',
      '^engine%.breath_pulled',
      '^engine%.breath_pushed',
      '^engine%.breath_ticked',
      '^engine%.commited_counters',
      '^engine%.polled_timers',
      '^engine%.wakeup_from_sleep'
   })
   table.sort(engine_events, self.sort_events_by_median_lag())
   self:html_boxplot(out, engine_events, 'tsc', 'engine_summary')
   out:write("<details>\n")
   out:write("<summary>Sleep</summary>\n")
   self:html_histogram(out, self.sleep, 'usec', 'sleep_usec')
   out:write("</details>\n")
   out:write("</details>\n")

   out:write("<details>\n")
   out:write("<summary>App summary</summary>\n")
   local app_events = self:select_events(self.events, {
      '^app%.pulled',
      '^app%.pushed',
      '^app%.ticked'
   })
   table.sort(app_events, self:sort_events_by_median_lag())
   self:html_boxplot(out, app_events, 'tsc', 'app_summary')
   out:write("</details>\n")

   out:write("<details>\n")
   out:write("<summary>Event lag</summary>\n")
   local all_events = self:select_events(self.events)
   table.sort(all_events, self:sort_events_by_name())
   out:write("<div class=scroll>\n")
   out:write("<table>\n")
   out:write("<tbody>\n")
   for _, event in ipairs(all_events) do
      out:write("<tr><td>\n")
      out:write("<details>\n")
      out:write(("<summary>%s</summary>\n"):format(event.message.name))
      local etcount = self:estimated_total_count(event)
      out:write(("<p>Estimated total count: %s (%s per second)</p>\n")
         :format(comma_value(round(etcount)), comma_value(round(etcount/self.event_period))))
      if event.lag then
         local etlag = self:estimated_total_lag(event)
         out:write(("<p>Estimated total lag: %s tsc (%d%%)</p>\n")
            :format(comma_value(round(etlag)), math.floor(100*etlag/(self.event_period*self.tsc_freq))))
         self:html_histogram(out, event.lag, 'tsc', 'event_'..event.message.name)
      end
      out:write("</details>\n")
      out:write("</td></tr>\n")
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
   out:write("</details>\n")
end

return Timeline
