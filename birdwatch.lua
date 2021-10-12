local audit = require("audit")
local vmprofile = require("audit.vmprofile")
local IR = require("audit.ir")

local Birdwatch = {}

function Birdwatch:new (arg)
   local self = setmetatable({}, {__index=Birdwatch})
   self.name = arg.name
   self.auditlog = audit:new(arg.auditlog)
   for _, profile in ipairs(arg.profiles) do
      self.auditlog:add_profile(profile)
   end
   return self
end

function Birdwatch:html_report (out)
   out:write("<meta charset='utf-8'>\n")
   self:html_report_style(out)
   self:html_report_profile_snapshots(out)
   self:html_report_traces(out)
   self:html_report_events(out)
   self:html_report_script(out)
end

local function percent (n, total) return n/total*100 end

function Birdwatch:html_report_profile_snapshots (out)
   out:write("<details>\n")
   out:write("<summary>Profiles</summary>\n")
   local snapshots = {}
   local now = self.auditlog.latest_snapshot
   for _=1,5 do
      snapshots[#snapshots+1] = {
         profiles = self.auditlog:select_profiles(now-1, now),
         size = 'second',
      }
      now = now - 1
   end
   for _=1,2 do
      snapshots[#snapshots+1] = {
         profiles = self.auditlog:select_profiles(now-60, now),
         size = 'minute',
      }
      now = now - 60
   end
   for _=1,1 do
      snapshots[#snapshots+1] = {
         profiles = self.auditlog:select_profiles(now-60*60, now),
         size = 'hour',
      }
      now = now - 60*60
   end
   -- Stacks
   out:write("<div class=profile-snapshots>")
   for i=#snapshots, 1, -1 do
      local snap = snapshots[i]
      out:write(("<div class=snapshot-stack snapshot=snapshot-%d %s>")
         :format(i, snap.size))
      local by_name = {}
      local total_samples = 0
      for name, profile in pairs(snap.profiles) do
         by_name[#by_name+1] = name
         total_samples = total_samples + profile:total_samples()
      end
      table.sort(by_name)
      for _, name in ipairs(by_name) do
         local profile = snap.profiles[name]
         local share = percent(profile:total_samples(), total_samples)
         if share >= 0.5 then
            out:write(("<div class=portion style='height:%.0fpx;' profile='%s' title='%s (%.1f%%)'></div>")
               :format(share, name, name, share))
         end
      end
      out:write("</div>")
   end
   out:write("</div>")
   -- Tabs
   out:write("<div class=profiles>")
   for i, snapshot in pairs(snapshots) do
      out:write(("<div class=snapshot id=snapshot-%d>"):format(i))
      self:html_report_profiles(snapshot.profiles, out)
      out:write("</div>")
   end
   out:write("</div>")
   out:write("</details>\n")
end

function Birdwatch:html_report_profiles (profiles, out)
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
   out:write("<div class='scroll short'>\n")
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
   -- Relations
   out:write("<details>\n")
   out:write("<summary>Relations</summary>\n")
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr><th>Parent</th></tr>\n")
   out:write("</thead>\n")
   out:write("</tr>\n")
   out:write("<tbody>\n")
   out:write("<tr><td>\n")
   local parent = trace:parent()
   if parent then
      out:write(("<a href=#trace-%d>%s</a>\n"):format(parent.traceno, parent))
   else
      out:write("None, this is a root trace")
   end
   out:write("</td></tr>\n")
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("<div class='scroll short'>\n")
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr><th>Children</th></tr>\n")
   out:write("</thead>\n")
   out:write("</tr>\n")
   out:write("<tbody>\n")
   local children = trace:children()
   for _, child in ipairs(children) do
      out:write("<tr>\n")
      out:write(("<td><a href=#trace-%d>%s</a></td>\n")
         :format(child.traceno, child))
      out:write("</tr>\n")
   end
   if #children == 0 then
      out:write("<tr><td>None</td></tr>\n")
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
   out:write("</details>\n")
   -- Contour
   out:write("<details>\n")
   out:write("<summary>Function contour</summary>\n")
   self:html_report_contour(trace:contour(), out)
   out:write("</details>\n")
   -- Bytecodes
   out:write("<details>\n")
   out:write("<summary>Bytecodes</summary>\n")
   self:html_report_bytecodes(trace:bytecodes(), out)
   out:write("</details>\n")
   -- Instructions
   out:write("<details>\n")
   out:write("<summary>Instructions</summary>\n")
   self:html_report_instructions(trace:instructions(), out, trace.traceno)
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
   if event.event == 'trace_stop' then
      out:write(("<summary>%s</summary>\n"):format(event))
      out:write(("<p>Creation of <a href=#trace-%d>%s</a></p>\n")
         :format(event.trace.traceno, event.trace))
   elseif event.event == 'trace_abort' then
      if event.trace_abort.jit_State.final ~= 0 then
         out:write(("<summary class=final-abort>%s</summary>\n"):format(event))
         out:write("<p><em><b>Final trace abort!</b></em> ")
         out:write("Starting location of trace is now blacklisted.</p>")
      else
         out:write(("<summary>%s</summary>\n"):format(event))
         out:write("<p>Trace abort is not final.</p>")
      end
      -- Contour
      out:write("<details>\n")
      out:write("<summary>Contour</summary>\n")
      self:html_report_contour(event.trace_abort:contour(), out)
      out:write("</details>\n")
      -- Bytecodes
      out:write("<details>\n")
      out:write("<summary>Bytecode log</summary>\n")
      self:html_report_bytecodes(event.trace_abort:bytecodes(), out)
      out:write("</details>\n")
   end
   out:write("</details>\n")
end

function Birdwatch:html_report_contour (contour, out)
   out:write("<pre class='scroll short'>\n")
   for _, info in ipairs(contour) do
      out:write(("%s%s:%d:%s:%d\n"):format(
            (' '):rep(info.framedepth*3),
            info.chunkname,
            info.chunkline,
            info.declname,
            info.chunkline-info.declline))
   end
   out:write("</pre>\n")
end

function Birdwatch:html_report_bytecodes (bytecodes, out)
   out:write("<div class='scroll short'>\n")
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr>\n")
   out:write("<th>#</th>\n")
   out:write("<th>Opcode</th>\n")
   out:write("<th>A</th>\n")
   out:write("<th>B</th>\n")
   out:write("<th>C</th>\n")
   out:write("<th>D</th>\n")
   out:write("<th>Hint</th>\n")
   out:write("</tr>\n")
   out:write("</thead>\n")
   out:write("<tbody>\n")
   for i, bc in ipairs(bytecodes) do
      out:write("<tr>\n")
      out:write(("<td class=right><tt>%04x</tt></td>\n"):format(i-1))
      if bc.name then
         out:write(("<td><tt>%s</tt></td>\n"):format(bc.name))
         for _, operand in ipairs{'a', 'b', 'c' ,'d'} do
            if bc[operand] then
               if type(bc[operand]) == 'number' then
                  out:write(("<td>%d</td>\n"):format(bc[operand]))
               elseif type(bc[operand]) == 'string' then
                  out:write(("<td><tt>%s</tt></td>\n"):format(bc[operand]))
               end
            elseif not (bc.j and operand == 'd') then
               out:write("<td></td>\n")
            end
         end
         if bc.j then
            local target = i+1+bc.j
            out:write(("<td class=right>⇒ <tt>%04x</tt></td>\n"):format(target))
         end
         out:write(("<td><em>%s</em></td>\n"):format(bc.hint))
      end
      out:write("</tr>\n")
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
end

function Birdwatch:html_report_instructions (instructions, out, traceno)
   local function iropclass (opcode)
      for _, kind in ipairs{'Loop', 'Phi', 'Memref', 'Load', 'Store',
                            'Guard', 'Alloc', 'Barrier', 'Call'}
      do
         if IR.Op[kind][opcode] then return kind end
      end
      return 'Misc'
   end
   out:write("<div class='scroll short'>\n")
   out:write("<table>\n")
   out:write("<thead>\n")
   out:write("<tr>\n")
   out:write("<th>#</th>\n")
   out:write("<th>Sunk?</th>\n")
   out:write("<th>Register/Slot</th>\n")
   out:write("<th>Type</th>\n")
   out:write("<th>Opcode</th>\n")
   out:write("<th>Left</th>\n")
   out:write("<th>Right</th>\n")
   out:write("<th>Hint</th>\n")
   out:write("</tr>\n")
   out:write("</thead>\n")
   out:write("<tbody>\n")
   for i, ins in ipairs(instructions) do
      if ins.opcode == 'nop' then goto skip end
      out:write(("<tr id=ins-%d-%d>\n"):format(traceno, i))
      out:write(("<td class=right><tt>%d</tt></td>\n"):format(i))
      out:write(("<td>%s</td>\n"):format(ins.sunk and '>' or ''))
      out:write(("<td><tt>%s</tt></td>\n"):format(ins.reg or ins.slot or ''))
      out:write(("<td><small>%s</small></td>\n"):format(ins.t))
      out:write(("<td class=irop-%s><tt><b>%s</b></tt></td>\n")
         :format(iropclass(ins.opcode), ins.opcode))
      for _, op in ipairs{'op1', 'op2'} do
         local val = ins[op]
         if type(val) == 'number' then
            out:write(("<td class=right>%s%s</td>\n")
               :format(val < 0 and '-' or '+', val))
         elseif type(val) == 'cdata' then
            out:write(("<td class=right><abbr title=%s>0x%x</abbr></td>\n")
               :format(tostring(val):gsub("ULL", ""), val))
         elseif type(val) == 'string' then
            if val:match("^%[(%d+)%]$") then
               local ref = tonumber(val:match("%[(%d+)%]"))
               out:write(("<td class=right><tt><a href=#ins-%d-%d>%d</a></tt></td>\n")
                  :format(traceno, ref, ref))
            elseif val:match("^#%d+$") then
               out:write(("<td class=right><tt>%s</tt></td>\n"):format(val))
            elseif val:match("^<flags[^>]+>$") then
               local flags = val:match("<flags ?([^>]*)>")
               out:write(("<td><span class=irflags>%s</span></td>\n")
                  :format(flags))
            elseif val:match("^<func[^>]+>$") then
               local func = val:match("<func ?([^>]*)>")
               local short = func:match(":([^:]+)$") or "func"
               out:write(("<td><span class=irfunc><abbr title='%s'>%s</abbr></span></td>\n")
                  :format(func, short))
            elseif val:match("^<ctype[^>]+>$") then
               local ctype = val:match("<ctype ?([^>]*)>")
               out:write(("<td><span class=irctype>%s</span></td>\n")
                  :format(ctype))
            elseif val:match("^<[^>]+>$") then
               local tag, more = val:match("<([a-z]+) ?([^>]*)>")
               out:write(("<td><span class=irnyi><abbr title='%s'>%s</abbr></span></td>\n")
                  :format(more, tag))
            else
               out:write(("<td><small>\"%s\"</small></td>\n"):format(val))
            end
         else
            out:write("<td></td>\n")
         end
      end
      out:write(("<td><small><em>%s</em></small></td>\n"):format(ins.hint))
      out:write("</tr>\n")
      ::skip::
   end
   out:write("</tbody>\n")
   out:write("</table>\n")
   out:write("</div>\n")
end

function Birdwatch:html_report_style (out)
   out:write([[<style>
      //body { display: flex; align-items: flex-start; }
      details { margin: 0.25em; padding: 0.25em; padding-left: 1em;
                border-radius: 0.25em; border: thin solid #ccc;
                background: white; overflow: auto; }
      summary { cursor: pointer; font-weight: bold; font-size: smaller; }
      details > *:nth-child(2) { margin-top: 0.5em; }

      abbr:hover { cursor: pointer; }

      summary:hover { color: #0d51bf; }
      *[focus] { box-shadow: 0 0 0.5em #0d51bf; }
      tr[focus] { box-shadow: none; background: #0d51bf30 !important; }

      summary.final-abort { color: red; }

      table { border-collapse: collapse; }
      th { font-size: smaller; color: #333; background: #f4f4f4; }
      td, th { padding: 0.4em 0.5em; }
      thead { position: sticky; top: 0; }
      tbody > tr:nth-of-type(even) { background: #f4f4f4; }
      td.right { text-align: right; }

      pre { padding-top: 0.25em; }

      .scroll { overflow: auto; max-height: 60vh;
                border-top: thin solid #ccc; }
      .short { max-height: 30vh; }

      span.irflags { border: solid thin #777; border-radius: 1em;
                     padding: 0 0.3em; font-size: small;
                     color: #333; background: #ffe995; }
      span.irfunc  { border: solid thin #777; border-radius: 1em;
                     padding: 0 0.3em; font-size: small;
                     color: #333; background: #e2deff; }
      span.irctype { border: solid thin #777; border-radius: 1em;
                     padding: 0 0.3em; font-size: small;
                     color: #333; background: #ebf4ff; }
      span.irnyi   { border: solid thin #777; border-radius: 1em;
                     padding: 0 0.3em; font-size: small;
                     color: #333; background: #ebebeb; }

      .irop-Barrier { color: #a10705; }
      .irop-Load, .irop-Memref { color: #0d52bf; }
      .irop-Store { color: #3a9104; }
      .irop-Guard { color: #d48e15; }
      .irop-Loop { background: #f4679d; }
      .irop-Phi { color: #bc245d; }
      .irop-Alloc { background: #9bdb4d; }
      .irop-Call { color: #7239b3; }

      .portion { width: 100%; cursor: pointer; border: thin solid white; }
      .portion:first-child { border-radius: 0.5em 0.5em 0 0; }
      .portion:last-child { border-radius: 0 0 0.5em 0.5em; }
      .snapshot-stack { width: 30px; margin: 2px; }
      .snapshot-stack[minute] { width: 60px; }
      .snapshot-stack[hour] { width: 120px; }
      .profile-snapshots { /*width: 70px;*/ display: flex; overflow: auto; }
  
      .snapshot { display: none; }

      </style>]])
end

function Birdwatch:html_report_script (out)
  out:write([[<script>
     var current_focus = false
     var current_hover = false
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
       history.pushState({}, href, href)
     }
     function highlight_on_href (event) {
      var href = event.target.getAttribute('href')
      var dest = document.querySelector(href)
      if (current_hover && !(current_hover === current_focus))
        current_hover.removeAttribute('focus')
      current_hover = dest
      current_hover.setAttribute('focus', '')
    }
    document.querySelectorAll("a").forEach(a => {
       if (a.getAttribute('href'))
         a.addEventListener('click', expand_on_href)
         a.addEventListener('mouseover', highlight_on_href)
     })

     var openTab = false
     function openProfilesTabForSnapshot (stack) {
         if (openTab)
             openTab.style = "display: none;"
         while (stack && !stack.getAttribute("snapshot"))
             stack = stack.parentNode
         let snapshot = stack.getAttribute("snapshot")
         let tab = document.querySelector('#' + snapshot)
         tab.style = "display: block;"
         openTab = tab
     }
     document.querySelectorAll(".snapshot-stack").forEach(el => {
         el.addEventListener('click', ev => openProfilesTabForSnapshot(ev.target))
     })
 
     function colorhash (str) {
         var h = 0;
         for (var i=0; i < str.length; i++) {
             h += fmix32(str.charCodeAt(i))
             h %= 2**32
         }
         return "hsl(" + (h % 256) + " 90% 60%)"
     }
     // Murmur3 fmix32
     function fmix32 (h) {
         h ^= h >> 16
         h *= 0x85ebca6b
         h ^= h >> 13
         h *= 0xc2b2ae35
         h ^= h >> 16
         return h
     }
     document.querySelectorAll(".portion").forEach(el => {
         el.style.background = colorhash(el.getAttribute("profile"))
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

function Birdwatch.snapshot (shmpath, snappath, keep_for)
   local find_vmprofile =
      ("find '%s' -name '*.vmprofile' 2>/dev/null"):format(shmpath)
   for path in readcmd(find_vmprofile, "*a"):gmatch("([^\n]+)\n") do
      local profile = vmprofile:new(path)
      local snap = ("%s.%d"):format(path:gsub(shmpath, snappath, 1), os.time())
      local dir = dirname(snap)
      print("mkdir", dir)
      mkdir(dir)
      print(path, "->", snap)
      profile:dump(snap)
   end
   local ls1 =
      ("ls -1 '%s' 2>/dev/null"):format(snappath)
   for name in readcmd(ls1, "*a"):gmatch("([^\n]+)\n") do
      if not can_open(shmpath.."/"..name) then
         print("unlink", snappath.."/"..name)
         unlink(snappath.."/"..name)
      end
   end
   local find_snap =
      ("find '%s' -name '*.vmprofile.*' 2>/dev/null"):format(snappath)
   keep_for = keep_for or 60*60
   local keep_from = os.time() - keep_for
   for path in readcmd(find_snap, "*a"):gmatch("([^\n]+)\n") do
      local timestamp = tonumber(path:match("([%d]+)$"))
      if timestamp < keep_from then
         print("unlink", path)
         unlink(path)
      end
   end
end

function readcmd (command, what)
   local f = io.popen(command)
   local value = f:read(what)
   f:close()
   return value
end

function can_open (filename, mode)
    mode = mode or 'r'
    local f = io.open(filename, mode)
    if f == nil then return false end
    f:close()
    return true
end

function basename (path)
   local cmd = ("basename '%s' 2>/dev/null"):format(path)
   return (readcmd(cmd, "*l"):gsub("\n",''))
end

function dirname (path)
   local cmd = ("dirname '%s' 2>/dev/null"):format(path)
   return (readcmd(cmd, "*l"):gsub("\n",''))
end

function mkdir (path)
   assert(os.execute(("mkdir -p '%s'"):format(path)))
end

function unlink (path)
   assert(os.execute(("rm -rf '%s'"):format(path)))
end

Birdwatch.snapshot("test/runsnabb", "test/snap", 10)

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
