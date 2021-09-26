local audit = require("audit")

local Birdwatch = {}

function Birdwatch:new (arg)
   local self = setmetatable({}, {__index=Birdwatch})
   self.auditlog = audit:new(arg.auditlog)
   for _, profile in ipairs(arg.profiles) do
      self.auditlog:add_profile(profile)
   end
   return self
end

function Birdwatch:html_report (out)
   self:html_report_style(out)
   self:html_report_profiles(out)
   self:html_report_traces(out)
   self:html_report_events(out)
   self:html_report_script(out)
end

local function percent (n, total) return n/total*100 end

function Birdwatch:html_report_profiles (out)
   out:write("<details>\n")
   out:write("<summary>Profiles</summary>\n")
   local profiles = self.auditlog:select_profiles()
   local total_samples = 0
   local by_name_sorted = {}
   for name, profile in pairs(profiles) do
      total_samples = total_samples + profile:total_samples()
      by_name_sorted[#by_name_sorted+1] = name
   end
   local function by_samples (x, y)
      return profiles[x]:total_samples() > profiles[y]:total_samples()
   end
   table.sort(by_name_sorted, by_samples)
   for _, name in pairs(by_name_sorted) do
      local profile = profiles[name]
      if profile:total_samples() > 0 then
         out:write("<details>\n")
         out:write(("<summary>%s (%.1f%%)</summary>\n")
            :format(name, percent(profile:total_samples(), total_samples)))
         self:html_report_profile(profile, out)
         out:write("</details>\n")
      end
   end
   out:write("</details>\n")
end
      
function Birdwatch:html_report_profile (profile, out)
   local total_samples = profile:total_samples()
   local vmst_samples = profile:total_vmst_samples()
   -- vmst totals
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr>\n")
   for _, vmst in pairs(profile.vmstates) do
      out:write(("<th>%s%%</th>\n"):format(vmst))
   end
   out:write("</tr>\n")
   out:write("</thead>\n")
   out:write("<tbody>\n")
   out:write("<tr>\n")
   for _, vmst in pairs(profile.vmstates) do
      out:write(("<td class=right>%.1f</td>\n")
         :format(percent(vmst_samples[vmst], total_samples)))
   end
   out:write("</tr>\n")
   out:write("</tbody>\n")
   out:write("</table>\n")
   -- hot traces
   local hot_traces = profile:hot_traces()
   out:write("<details>\n")
   out:write("<summary>Hot traces</summary>\n")
   out:write("<div class=scroll>\n")
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr>\n")
   out:write("<th>Trace</th>\n")
   out:write("<th>total%</th>\n")
   --out:write("<th>Samples</th>\n")
   for _, vmst in pairs(profile.vmstates) do
      out:write(("<th>%s%%</th>\n"):format(vmst))
   end
   out:write("</tr>\n")
   out:write("</thead>\n")
   out:write("<tbody>\n")
   for _, hot in ipairs(hot_traces) do
      out:write("<tr>\n")
      if hot.traceno then
         out:write(("<td><a href=#trace-%d>%s</a></td>\n"):format(
               hot.traceno, self.auditlog.traces[hot.traceno]))
      else
         out:write("<td>Untraced</td>")
      end
      out:write(("<td class=right>%.1f</td>\n"):format(
            percent(hot.total, total_samples)))
      --out:write(("<td class=right>%d</td>\n"):format(trace.total))
      for _, vmst in pairs(profile.vmstates) do
         out:write(("<td class=right>%.1f</td>\n")
            :format(percent(hot.vmst[vmst], hot.total)))
      end
      out:write("</tr>\n")
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
   out:write("</details>\n")
end

function Birdwatch:html_report_traces (out)
   local by_traceno = {}
   for traceno, _ in pairs(self.auditlog.traces) do
      by_traceno[#by_traceno+1] = traceno
   end
   table.sort(by_traceno)
   out:write("<details>\n")
   out:write("<summary>Traces</summary>\n")
   out:write("<div class=scroll>\n")
   for _, traceno in ipairs(by_traceno) do
      local trace = self.auditlog.traces[traceno]
      out:write(("<details id=trace-%d>\n"):format(traceno))
      out:write(("<summary>%s</summary>\n"):format(trace))
      self:html_report_trace(trace, out)
      out:write("</details>\n")
   end
   out:write("</div>\n")
   out:write("</details>\n")
end

function Birdwatch:html_report_trace (trace, out)
   -- Contour
   out:write("<details>\n")
   out:write("<summary>Function contour</summary>\n")
   out:write("<pre class='scroll short'>\n")
   for _, info in ipairs(trace:contour()) do
      out:write(("%s%s:%d:%s:%d\n"):format(
            (' '):rep(info.framedepth*3),
            info.chunkname,
            info.chunkline,
            info.declname,
            info.chunkline-info.declline))
   end
   out:write("</pre>\n")
   out:write("</details>\n")
   -- Events
   out:write("<details>\n")
   out:write("<summary>Events</summary>\n")
   out:write("<div class='scroll short'>\n")
   out:write("<table>\n")
   out:write("<tbody>\n")
   for _, event in ipairs(trace:events()) do
      out:write("<tr>\n")
      out:write(("<td class=right>%.3fs</td>\n"):format(event:reltime()))
      out:write(("<td><a href=#event-%d>%s</a></td>\n"):format(event.id, event))
      out:write("</tr>\n")
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
   out:write("</details>\n")
end

function Birdwatch:html_report_events (out)
   out:write("<details>\n")
   out:write("<summary>Trace events</summary>\n")
   out:write("<div class=scroll>\n")
   out:write("<table>\n")
   out:write("<tbody>\n")
   for _, event in pairs(self.auditlog.events) do
      if event.event:match("trace") then
         out:write("<tr>")
         --out:write(("<td class=right>#%d</td>\n"):format(event.id))
         out:write(("<td class=right>%.3fs</td>\n"):format(event:reltime()))
         out:write("<td>\n")
         self:html_report_event(event, out)
         out:write("</td>\n")
         out:write("</tr>\n")
      end
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</>\n")
   out:write("</details>\n")
end

function Birdwatch:html_report_event (event, out)
   out:write(("<details id=event-%d>\n"):format(event.id))
   out:write(("<summary>%s</summary>\n"):format(event))
   if event.event == 'trace_stop' then
      out:write(("<p>Creation of <a href=#trace-%d>%s</a></p>\n")
         :format(event.trace.traceno, event.trace))
   end
   out:write("</details>\n")
end

function Birdwatch:html_report_style (out)
   out:write([[<style>
      //body { display: flex; align-items: flex-start; }
      details { margin: 0.25em; padding: 0.25em; padding-left: 1em;
                border-radius: 0.25em; border: thin solid #ccc;
                overflow: auto; }
      summary { cursor: pointer; font-weight: bold; font-size: smaller; }
      details > *:nth-child(2) { margin-top: 0.5em; }

      summary:hover { color: #0d51bf; }
      *[focus] { box-shadow: 0 0 0.5em #0d51bf; }

      table { border-collapse: collapse; }
      th { font-size: smaller; color: #333; background: #f4f4f4; }
      td, th { padding: 0.4em 0.5em; }
      thead { position: sticky; top: 0; }
      tbody > tr:nth-of-type(even) { background: #f4f4f4; }
      td.right { text-align: right; }

      .scroll { overflow: auto; max-height: 30vh;
                border-top: thin solid #ccc; }
      .short { max-height: 12vh; }

      </style>]])
end

function Birdwatch:html_report_script (out)
  out:write([[<script>
     var current_focus = false
     function expand_details (element) {
       if (element.tagName == 'DETAILS')
         element.setAttribute('open', '')
       if (element.parentElement)
         expand_details(element.parentElement)
     }
     function expand_on_href (event) {
       var href = event.target.getAttribute('href')
       var dest = document.querySelector(href)
       expand_details(dest)
       if (current_focus)
         current_focus.removeAttribute('focus')
       current_focus = dest
       current_focus.setAttribute('focus', '')
       event.preventDefault()
       dest.scrollIntoView({block: 'center'})
     }
     document.querySelectorAll("a").forEach(a => {
       if (a.getAttribute('href'))
         a.addEventListener('click', expand_on_href)
     })
</script>]])
end

function Birdwatch:socket_activate (stdin, stdout)
   -- HTTP/1.1 sorta
   local request = stdin:read("l")
   assert(get:match("^GET"), "Not a GET request")
   stdout:write("HTTP/1.1 200 OK\r\n")
   stdout:write("Content-Type: text/html\r\n")
   stdout:write("\r\n")
   self:html_report(stdout)
end

B = Birdwatch:new{
   auditlog = "test/snabb-basic1/audit.log",
   profiles = {"test/snabb-basic1/vmprofile/apps.basic.basic_apps.vmprofile",
               "test/snabb-basic1/vmprofile/engine.vmprofile",
               "test/snabb-basic1/vmprofile/program.vmprofile"}
}

local f = assert(io.open("out.html", "w"))
B:html_report(f)
assert(f:write("\n"))
f:close()
