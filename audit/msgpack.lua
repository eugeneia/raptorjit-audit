local ffi = require("ffi")
local band, bor, bswap, rshift = bit.band, bit.bor, bit.bswap, bit.rshift

-- msgpack reader - see http://msgpack.org/index.html

assert(ffi.abi("le")) -- XXX assumes little endian cpu.

-- msgpack.read(unsigned char *, number) -> object, number
--    Read msgpack object starting at data+offset.
--    Return parsed object and size of msgpack encoded object (bytes consumed).
function read (data, offset)
   if band(data[offset], 0xf0) == 0x80 then
      return read_fixmap(data, offset)
   elseif  data[offset]        == 0xda then
      return read_str16(data, offset)
   elseif  data[offset]        == 0xcf then
      return read_uint64(data, offset)
   elseif  data[offset]        == 0xc6 then
      return read_bin32(data, offset)
   else
      error(("NYI: %x at offset %d"):format(data[offset], offset))
   end
end

-- msgpack: key/value map
local fixmap_t = ffi.typeof[[struct {
   uint8_t tag; uint8_t objects[1];
}__attribute__((packed))]]
local fixmap_ptr_t = ffi.typeof("$*", fixmap_t)
function read_fixmap (data, offset)
   offset = offset or 0
   data = ffi.cast(fixmap_ptr_t, data+offset)
   assert(band(data.tag, 0xf0) == 0x80)
   local npairs = band(data.tag, 0xf)
   local ret = {}
   local index = 0
   for _=1, npairs do
      local key, len = read(data.objects, index)
      index = index + len
      local value, len = read(data.objects, index)
      index = index + len
      ret[key] = value
   end
   return ret, ffi.sizeof(fixmap_t) + index-1
end

-- msgpack: string with 16-bit length
local str16_t = ffi.typeof[[struct {
   uint8_t tag; uint16_t len; uint8_t str[1];
}__attribute__((packed))]]
local str16_ptr_t = ffi.typeof("$*", str16_t)
function read_str16 (data, offset)
   offset = offset or 0
   data = ffi.cast(str16_ptr_t, data+offset)
   assert(data.tag == 0xda)
   local len = rshift(bswap(data.len), 16)
   local ret = ffi.string(data.str, len)
   return ret, ffi.sizeof(str16_t) + len-1
end

-- msgpack: 64-bit unsigned integer
local uint64_t = ffi.typeof[[struct {
   uint8_t tag; uint64_t n;
}__attribute__((packed))]]
local uint64_ptr_t = ffi.typeof("$*", uint64_t)
function read_uint64 (data, offset)
   offset = offset or 0
   data = ffi.cast(uint64_ptr_t, data+offset)
   assert(data.tag == 0xcf)
   local ret = bswap(data.n)
   return ret, ffi.sizeof(uint64_t)
end

-- msgpack: byte string with 32-bit length
local bin32_t = ffi.typeof[[struct {
   uint8_t tag; uint32_t len; uint8_t data[1];
}__attribute__((packed))]]
local bin32_ptr_t = ffi.typeof("$*", bin32_t)
function read_bin32 (data, offset)
   offset = offset or 0
   data = ffi.cast(bin32_ptr_t, data+offset)
   assert(data.tag == 0xc6)
   local len = bswap(data.len)
   local ret = ffi.string(data.data, len)
   return ret, ffi.sizeof(bin32_t) + len-1
end

-- Module msgpack
return {
   read = read
}
