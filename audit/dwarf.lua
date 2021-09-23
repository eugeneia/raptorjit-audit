local ffi = require("ffi")
local band, bor, lshift = bit.band, bit.bor, bit.lshift

-- DWARF 4 parser
-- http://www.dwarfstd.org/Dwarf4Std.php

-- dwarf.new() -> DWARF
--    New DWARF object.
--
-- DWARF:add_section(string, string)
--    Add named section to DWARF object.
--
-- DWARF:load()
--    Load DWARF data from sections
--
-- DWARF:find_die(string) -> DIE|nil
--    Find DIE (debugging information entry) by name.
--
-- DWARF:enum_name(cvalue) -> string|nil
--    Return symbol for enum value.
--
-- DIE:ctype() -> ctype
--    Return ctype for DIE.
--
-- DIE:attributes() -> table
--    Return table of attribute values for DIE (refer to DWARF spec.)
--
-- DIE:members() -> iterator
--    Return indexed iterator over children of DIE.
--
-- DIE:print()
--    Print DIE (for debugging).

assert(ffi.abi("le")) -- XXX assumes little endian cpu.

local DWARF, DIE = {}, {}

function new_dwarf ()
   local self = {
      sections = {
         debug_info = false,
         debug_abbrev = false,
         debug_str = false,
         debug_str_offsets = false
      },
      parse = nil,
      str = nil,
      str_offsets = nil,
      abbrev = nil,
      die = nil,
      die_by_offset = {},
      die_by_name = nil,
      ctype_cache = {},
      enum_cache = {}
   }
   return setmetatable(self, {__index=DWARF})
end

function DWARF:add_section (name, data)
   name = name:match("%.([a-z_]+)%.dwo")
   if not name then return end
   for section, exists in pairs(self.sections) do
      if name == section then
         assert(not exists, "DWARF already has section: "..name)
         self.sections[name] = data
         break
      end
   end
end

-- DWARF header
local dwarf_t = ffi.typeof[[struct {
   uint32_t unit_length;
   uint16_t version;
   uint32_t debug_abbrev_offset;
   uint8_t  address_size;
   uint8_t  die[1];
} __attribute__((packed))]]
local dwarf_ptr_t = ffi.typeof("$*", dwarf_t)

function DWARF:load ()
   assert(self.sections.debug_info, "DWARF missing debug_info section")
   assert(self.sections.debug_abbrev, "DWARF missing debug_abbrev section")
   assert(self.sections.debug_str, "DWARF missing debug_str section")
   local h = ffi.cast(dwarf_ptr_t, self.sections.debug_info)
   assert(h.unit_length < 0xfffffff0)
   assert(h.version >= 4)
   assert(h.address_size == 8)
   self.str = ffi.cast("char *", self.sections.debug_str)
   if self.sections.debug_str_offsets then
      self.str_offsets = ffi.cast("char *", self.sections.debug_str_offsets)
   end
   self.abbrev = self:load_abbrev(self.sections.debug_abbrev,
                                  h.debug_abbrev_offset)
   self.die = self:load_die(h.die)
   self.die_by_name = self:resolve_die(self.die)
end

function DWARF:find_die (name)
   assert(self.die_by_name, "DWARF not loaded")
   return self.die_by_name[name]
end

function DWARF:enum_name (e)
   return self.enum_cache[tostring(e)]
end

function DIE:ctype ()
   return self.dwarf.ctype_cache[self] or self:build_ctype()
end

function DIE:attributes ()
   return self.values
end

function DIE:members ()
   return ipairs(self.children)
end

function DIE:print (indent)
   indent = indent or 0
   local spc = (' '):rep(indent)
   print(("%s(%d) %s"):format(spc, self.code, self.tag))
   for attribute, value in pairs(self.values) do
      if type(value) == 'table' then
         value = value.values.name or value
      end
      print(("%s %s=%s"):format(spc, attribute, value))
   end
   for _, child in ipairs(self.children) do
      child:print(indent+3)
   end
end


--
-- DWARF parsing
--

local DW_TAG = {
   [0x01] = "array_type",
   [0x02] = "class_type",
   [0x03] = "entry_point",
   [0x04] = "enumeration_type",
   [0x05] = "formal_parameter",
   [0x08] = "imported_declaration",
   [0x0a] = "label",
   [0x0b] = "lexical_block",
   [0x0d] = "member",
   [0x0f] = "pointer_type",
   [0x10] = "reference_type",
   [0x11] = "compile_unit",
   [0x12] = "string_type",
   [0x13] = "structure_type",
   [0x15] = "subroutine_type",
   [0x16] = "typedef",
   [0x17] = "union_type",
   [0x18] = "unspecified_parameters",
   [0x19] = "variant",
   [0x1a] = "common_block",
   [0x1b] = "common_inclusion",
   [0x1c] = "inheritance",
   [0x1d] = "inlined_subroutine",
   [0x1e] = "module",
   [0x1f] = "ptr_to_member_type",
   [0x20] = "set_type",
   [0x21] = "subrange_type",
   [0x22] = "with_stmt",
   [0x23] = "access_declaration",
   [0x24] = "base_type",
   [0x25] = "catch_block",
   [0x26] = "const_type",
   [0x27] = "constant",
   [0x28] = "enumerator",
   [0x29] = "file_type",
   [0x2a] = "friend",
   [0x2b] = "namelist",
   [0x2c] = "namelist_item",
   [0x2d] = "packed_type",
   [0x2e] = "subprogram",
   [0x2f] = "template_type_parameter",
   [0x30] = "template_value_parameter",
   [0x31] = "thrown_type",
   [0x32] = "try_block",
   [0x33] = "variant_part",
   [0x34] = "variable",
   [0x35] = "volatile_type",
   [0x36] = "dwarf_procedure",
   [0x37] = "restrict_type",
   [0x38] = "interface_type",
   [0x39] = "namespace",
   [0x3a] = "imported_module",
   [0x3b] = "unspecified_type",
   [0x3c] = "partial_unit",
   [0x3d] = "imported_unit",
   [0x3f] = "condition",
   [0x40] = "shared_type",
   [0x41] = "type_unit",
   [0x42] = "rvalue_reference_type",
   [0x43] = "template_alias",
   [0x4080] = "lo_user",
   [0xffff] = "hi_user"
}
local DW_CHILDREN = {
   [0x00] = false,
   [0x01] = true
}
local DW_AT = {
   [0x01] = "sibling", -- reference
   [0x02] = "location", -- exprloc, loclistptr
   [0x03] = "name", -- string
   [0x09] = "ordering", -- constant
   [0x0b] = "byte_size", -- constant, exprloc, reference
   [0x0c] = "bit_offset", -- constant, exprloc, reference
   [0x0d] = "bit_size", -- constant, exprloc, reference
   [0x10] = "stmt_list", -- lineptr
   [0x11] = "low_pc", -- address
   [0x12] = "high_pc", -- address, constant
   [0x13] = "language", -- constant
   [0x15] = "discr", -- reference
   [0x16] = "discr_value", -- constant
   [0x17] = "visibility", -- constant
   [0x18] = "import", -- reference
   [0x19] = "string_length", -- exprloc, loclistptr
   [0x1a] = "common_reference", -- reference
   [0x1b] = "comp_dir", -- string
   [0x1c] = "const_value", -- block, constant, string
   [0x1d] = "containing_type", -- reference
   [0x1e] = "default_value", -- reference
   [0x20] = "inline", -- constant
   [0x21] = "is_optional", -- flag
   [0x22] = "lower_bound", -- constant, exprloc, reference
   [0x25] = "producer", -- string
   [0x27] = "prototyped", -- flag
   [0x2a] = "return_addr", -- exprloc, loclistptr
   [0x2c] = "start_scope", -- constant, rangelistptr
   [0x2e] = "bit_stride", -- constant, exprloc, reference
   [0x2f] = "upper_bound", -- constant, exprloc, reference
   [0x31] = "abstract_origin", -- reference
   [0x32] = "accessibility", -- constant
   [0x33] = "address_class", -- constant
   [0x34] = "artificial", -- flag
   [0x35] = "base_types", -- reference
   [0x36] = "calling_convention", -- constant
   [0x37] = "count", -- constant, exprloc, reference
   [0x38] = "data_member_location", -- constant, exprloc, loclistptr
   [0x39] = "decl_column", -- constant
   [0x3a] = "decl_file", -- constant
   [0x3b] = "decl_line", -- constant
   [0x3c] = "declaration", -- flag
   [0x3d] = "discr_list", -- block
   [0x3e] = "encoding", -- constant
   [0x3f] = "external", -- flag
   [0x40] = "frame_base", -- exprloc, loclistptr
   [0x41] = "friend", -- reference
   [0x42] = "identifier_case", -- constant
   [0x43] = "macro_info", -- macptr
   [0x44] = "namelist_item", -- reference
   [0x45] = "priority", -- reference
   [0x46] = "segment", -- exprloc, loclistptr
   [0x47] = "specification", -- reference
   [0x48] = "static_link", -- exprloc, loclistptr
   [0x49] = "type", -- reference
   [0x4a] = "use_location", -- exprloc, loclistptr
   [0x4b] = "variable_parameter", -- flag
   [0x4c] = "virtuality", -- constant
   [0x4d] = "vtable_elem_location", -- exprloc, loclistptr
   [0x4e] = "allocated", -- constant, exprloc, reference
   [0x4f] = "associated", -- constant, exprloc, reference
   [0x50] = "data_location", -- exprloc
   [0x51] = "byte_stride", -- constant, exprloc, reference
   [0x52] = "entry_pc", -- address
   [0x53] = "use_UTF8", -- flag
   [0x54] = "extension", -- reference
   [0x55] = "ranges", -- rangelistptr
   [0x56] = "trampoline", -- address, flag, reference, string
   [0x57] = "call_column", -- constant
   [0x58] = "call_file", -- constant
   [0x59] = "call_line", -- constant
   [0x5a] = "description", -- string
   [0x5b] = "binary_scale", -- constant
   [0x5c] = "decimal_scale", -- constant
   [0x5d] = "small", -- reference
   [0x5e] = "decimal_sign", -- constant
   [0x5f] = "digit_count", -- constant
   [0x60] = "picture_string", -- string
   [0x61] = "mutable", -- flag
   [0x62] = "threads_scaled", -- flag
   [0x63] = "explicit", -- flag
   [0x64] = "object_pointer", -- reference
   [0x65] = "endianity", -- constant
   [0x66] = "elemental", -- flag
   [0x67] = "pure", -- flag
   [0x68] = "recursive", -- flag
   [0x69] = "signature", -- reference
   [0x6a] = "main_subprogram", -- flag
   [0x6b] = "data_bit_offset", -- constant
   [0x6c] = "const_expr", -- flag
   [0x6d] = "enum_class", -- flag
   [0x6e] = "linkage_name", -- string
   [0x2000] = "lo_user", -- ---
   [0x3fff] = "hi_user" -- ---
}
local DW_FORM = {
   [0x01] = "addr", -- address
   [0x03] = "block2", -- block
   [0x04] = "block4", -- block
   [0x05] = "data2", -- constant
   [0x06] = "data4", -- constant
   [0x07] = "data8", -- constant
   [0x08] = "string", -- string
   [0x09] = "block", -- block
   [0x0a] = "block1", -- block
   [0x0b] = "data1", -- constant
   [0x0c] = "flag", -- flag
   [0x0d] = "sdata", -- constant
   [0x0e] = "strp", -- string
   [0x0f] = "udata", -- constant
   [0x10] = "ref_addr", -- reference
   [0x11] = "ref1", -- reference
   [0x12] = "ref2", -- reference
   [0x13] = "ref4", -- reference
   [0x14] = "ref8", -- reference
   [0x15] = "ref_udata", -- reference
   [0x16] = "indirect", -- (see Section 7.5.3)
   [0x17] = "sec_offset", -- lineptr, loclistptr, macptr, rangelistptr
   [0x18] = "exprloc", -- exprloc
   [0x19] = "flag_present", -- flag
   [0x20] = "ref_sig8", -- reference
   [0x1f02] = "indexed_string" -- Non-standard GNU extension? (Exists in DWARF5)
}
function dwarf_tag (data)
   local tag, data = leb128(data)
   if tag == 0 then return nil, data end
   return DW_TAG[tag] or 'unknown', data
end
function dwarf_children (data)
   return DW_CHILDREN[data[0]], data+1
end
function dwarf_at (data)
   local at, data = leb128(data)
   if at == 0 then return nil, data end
   return DW_AT[at] or 'unknown', data
end
function dwarf_form (data)
   local form, data = leb128(data)
   if form == 0 then return nil, data end
   return assert(DW_FORM[form]), data
end

function DWARF:load_abbrev (data, offset)
   data = ffi.cast("uint8_t *", data) + offset
   local ret = {}
   while true do
      local a = {attributes={}}
      a.code, data = leb128(data)
      if a.code == 0 then break end
      a.tag, data = dwarf_tag(data)
      a.has_children, data = dwarf_children(data)
      while true do
         local at, form
         at, data = dwarf_at(data)
         form, data = dwarf_form(data)
         if at ~= nil then
            a.attributes[#a.attributes+1] = {at, form}
         elseif form == nil then break end
      end
      ret[a.code] = a
   end
   return ret
end

local function t_parser (t)
   t = ffi.typeof(t)
   return function (data)
      return ffi.cast(ffi.typeof("$*", t), data)[0], data + ffi.sizeof(t)
   end
end
local function str_parser ()
   return function (data)
      local str = ffi.string(data)
      return str, data+#str+1
   end
end
local function strp_parser (str)
   local parse_offset = t_parser("uint32_t")
   local parse_str = str_parser()
   return function (data)
      local offset, data = parse_offset(data)
      return (parse_str(assert(str)+offset)), data
   end
end
local function indexed_str_parser (str, str_offsets)
   local offsets = ffi.cast("uint32_t *", str_offsets)
   local parse_strp = strp_parser(str)
   return function (data)
      -- Late assertion because indexed strings seem to be a non-standard GNU
      -- extension to DWARF 4.
      assert(offsets ~= nil, "DWARF missing debug_str_offsets section.")
      local index, data = leb128(data)
      return parse_strp(offsets+index), data
   end
end

function DWARF:load_die (data)
   -- Attribute value parsers
   if not self.parse then
      self.parse = {
         string = str_parser(),
         indexed_string = indexed_str_parser(self.str, self.str_offsets),
         data1 = t_parser("uint8_t"),
         sec_offset = t_parser("uint32_t"),
         data2 = t_parser("uint16_t"),
         data4 = t_parser("uint32_t"),
         data8 = t_parser("uint64_t"),
         ref4 = t_parser("uint32_t"),
         --flag = t_parser("bool"),
         flag_present = function (data) return true, data end,
      }
   end

   -- Offset of DIE in debug_info section
   local base = ffi.cast("uint8_t *", self.sections.debug_info)
   local offset = tonumber(data - base)

   -- Build the DIE
   local die = setmetatable(
      {values={}, children={}, dwarf=self},
      {__index=DIE}
   )
   die.code, data = leb128(data)
   if die.code == 0 then return nil, data end
   local abbrev = assert(self.abbrev[die.code])
   die.tag = abbrev.tag
   -- Parse attribute values
   for _, attr in ipairs(abbrev.attributes) do
      local at, form, value = unpack(attr)
      value, data = assert(self.parse[form], "NYI: "..form)(data)
      if at ~= 'unknown' then
         die.values[at] = value
      end
   end
   -- Parse children
   while abbrev.has_children do
      local child
      child, data = self:load_die(data)
      if child then
         die.children[#die.children+1] = child
      else
         break
      end
   end

   self.die_by_offset[offset] = die
   return die, data
end

function DWARF:resolve_die (die, by_name)
   by_name = by_name or {}
   if die.values.name then
      by_name[die.values.name] = die
   end
   for _, attr in ipairs(self.abbrev[die.code].attributes) do
      local at, form = unpack(attr)
      if form == "ref4" then
         die.values[at] = assert(self.die_by_offset[die.values[at]])
      end
   end
   for _, child in die:members() do
      self:resolve_die(child, by_name)
   end
   return by_name
end

-- Unsigned LEB128 decoder
-- https://en.wikipedia.org/wiki/LEB128
function leb128 (p)
   local result, shift = 0ULL, 0
   for i=0, 6 do
      result = bor(result, lshift(band(p[i], 0x7fULL), i*7))
      if band(p[i], 0x80) == 0 then
         return tonumber(result), p+i+1
      end
   end
   error("NYI: leb128 encoded integer > 53 bits")
end


--
-- DWARF based ctype building
--

function DIE:build_ctype ()
   local attr = self:attributes()
   if self.tag == 'structure_type' then
      local size = assert(self.values.byte_size)
      -- Resolve self references
      self.dwarf.ctype_cache[self] = ffi.typeof("uint8_t["..size.."]")
      local t = "struct {\n"
      local mt = {}
      local cur, npad = 0, 0
      for _, member in ipairs(self.children) do
         local pad = assert(member.values.data_member_location) - cur
         if pad > 0 then
            t = t.."unsigned char __pad"..npad.."__["..pad.."];\n"
            cur = cur + pad
            npad = npad + 1
         end
         local member_t = assert(member.values.type):ctype()
         mt[#mt+1] = member_t
         t = t.."$ "..(member.values.name or '')..";\n"
         cur = cur + ffi.sizeof(member_t)
      end
      local pad = size - cur
      if pad > 0 then
         t = t.."unsigned char __pad"..npad.."__["..pad.."];\n"
      end
      t = t.."} __attribute__((packed))"
      --print(t)
      t = ffi.typeof(t, unpack(mt))
      self.dwarf.ctype_cache[self] = t
      return t
   elseif self.tag == 'union_type' then
      local size = assert(self.values.byte_size)
      -- Resolve self references
      self.dwarf.ctype_cache[self] = ffi.typeof("uint8_t["..size.."]")
      local t = "union {\n"
      t = t.."unsigned char __pad__["..size.."];\n"
      local mt = {}
      for _, member in ipairs(self.children) do
         local member_t = assert(member.values.type):ctype()
         mt[#mt+1] = member_t
         t = t.."$ "..(member.values.name or '')..";\n"
      end
      t = t.."}"
      --print(t)
      t = ffi.typeof(t, unpack(mt))
      self.dwarf.ctype_cache[self] = t
      return t
   elseif self.tag == 'enumeration_type' then
      local t = "enum {\n"
      for _, member in ipairs(self.children) do
         assert(member.tag == 'enumerator')
         local name = assert(member.values.name)
         local value = assert(member.values.const_value)
         t = t..("%s=%d,\n"):format(name, value)
      end
      t = t.."}"
      --print(t)
      t = ffi.typeof(t)
      for _, member in ipairs(self.children) do
         assert(member.tag == 'enumerator')
         local name = assert(member.values.name)
         local value = assert(member.values.const_value)
         self.dwarf.enum_cache[tostring(ffi.cast(t, value))] = name
      end
      self.dwarf.ctype_cache[self] = t
      return t
   elseif self.tag == 'pointer_type' and not self.values.type or
          self.tag == 'subroutine_type'
   then
      return ffi.typeof("void *")
   elseif self.tag == 'pointer_type' or
          self.tag == 'array_type'
   then
      return ffi.typeof("$ *", assert(self.values.type):ctype())
   elseif self.tag == 'base_type' then
      return ffi.typeof(assert(self.values.name))
   elseif self.tag == 'member' or
          self.tag == 'typedef' or
          self.tag == 'variable' or
          self.tag == 'const_type'
   then
      return assert(self.values.type):ctype()
   else
      --self:print()
      error("NYI: "..self.tag)
   end
end


--
-- Module dwarf
--

return {
   new = new_dwarf
}
