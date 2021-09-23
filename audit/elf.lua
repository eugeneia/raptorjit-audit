local ffi = require("ffi")

-- ELF parser
-- https://wiki.osdev.org/ELF
-- https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Section_header

-- elf.new(string) -> ELF
--    Parse ELF object from string.
--
-- ELF:sections() -> iter(string,string)
--    Return iterator over section names and data.

assert(ffi.abi("le")) -- XXX assumes little endian cpu.

local ELF = {}

-- ELF file header
local elf_t = ffi.typeof[[struct {
   uint8_t magic;
   uint8_t elf[3];
   uint8_t arch;
   uint8_t endianness;
   uint8_t header_version;
   uint8_t os_abi;
   uint8_t pad1[8];
   uint16_t type;
   uint16_t machine;
   uint32_t version;
   uint64_t entry;
   uint64_t phoff;
   uint64_t shoff;
   uint32_t flags;
   uint16_t ehsize;
   uint16_t phentsize;
   uint16_t phnum;
   uint16_t shentsize;
   uint16_t shnum;
   uint16_t shstrndx;
} __attribute__((packed))]]
local elf_ptr_t = ffi.typeof("$*", elf_t)

-- ELF section header
local elf_section_t = ffi.typeof[[struct {
   uint32_t name;
   uint32_t type;
   uint64_t flags;
   uint64_t addr;
   uint64_t offset;
   uint64_t size;
   uint32_t link;
   uint32_t info;
   uint64_t align;
   uint64_t entsize;
} __attribute__((packed))]]
local elf_section_ptr_t = ffi.typeof("$*", elf_section_t)

function read_elf (data)
   data = ffi.cast("uint8_t *", data)
   local h = ffi.cast(elf_ptr_t, data)
   assert(h.magic == 0x7f)
   assert(ffi.string(h.elf, 3) == "ELF")
   assert(h.arch == 2) -- 64 bit
   assert(h.endianness == 1) -- little endian
   assert(h.shentsize == ffi.sizeof(elf_section_t))
   assert(h.shoff > 0)
   assert(h.shstrndx ~= 0, "Need section name table")
   local sh = ffi.cast(elf_section_ptr_t, data+h.shoff)
   local names = data+sh[h.shstrndx].offset
   local sections = {}
   for i=1, h.shnum-1 do
      sections[#sections+1] = {
         name = ffi.string(names+sh[i].name),
         data = ffi.string(data+sh[i].offset, sh[i].size)
      }
   end
   return setmetatable(sections, {__index=ELF})
end

function ELF:sections ()
   local ipair, _, idx = ipairs(self)
   return function ()
      idx = ipair(self, idx)
      if idx then
         return self[idx].name, self[idx].data
      end
   end
end

-- Module elf
return {
   new = read_elf
}
