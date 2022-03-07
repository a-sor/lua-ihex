--[[
  Intel HEX files (.hex) conversion.

  The author of this work hereby waives all claim of copyright (economic and
  moral) in this work and immediately places it in the public domain; it may
  be used, distorted or destroyed in any manner whatsoever without further
  attribution or notice to the creator.

  Intel HEX format description: https://en.wikipedia.org/wiki/Intel_HEX
]]

  -- Intel HEX record types
  local HEX_REC_DATA           = 0
  local HEX_REC_EOF            = 1
  local HEX_REC_EXT_SEG_ADDR   = 2
  local HEX_REC_START_SEG_ADDR = 3
  local HEX_REC_EXT_LIN_ADDR   = 4
  local HEX_REC_START_LIN_ADDR = 5

  local filler = IHEX_GAP_FILLER or 0xff

  local sprintf = string.format

  -----------------------------------------------------------------------------

local function parse_line(line)
  local slen, saddr1, saddr2, styp, sdata, scrc =
    line:match('^:(%x%x)(%x%x)(%x%x)(%x%x)(%x*)(%x%x)[\r]?$')

  if not slen then
    return nil, 'Error in line ' .. line
  end

  local len = tonumber(slen, 16)
  local addr1 = tonumber(saddr1, 16)
  local addr2 = tonumber(saddr2, 16)
  local typ = tonumber(styp, 16)
  local crc = tonumber(scrc, 16)

  if typ ~= HEX_REC_DATA and typ ~= HEX_REC_EOF and typ ~= HEX_REC_EXT_SEG_ADDR
     and typ ~= HEX_REC_START_SEG_ADDR and typ ~=  HEX_REC_EXT_LIN_ADDR
     and typ ~= HEX_REC_START_LIN_ADDR then
    return nil, 'Unknown record type in line ' .. line
  end

  if ((typ == HEX_REC_EXT_SEG_ADDR or typ == HEX_REC_EXT_LIN_ADDR) and len ~= 2) or
     ((typ == HEX_REC_START_SEG_ADDR or typ == HEX_REC_START_LIN_ADDR) and len ~= 4) then
    -- address value is ignored
    return nil, 'Record type does not match its length in line ' .. line
  end

  local compl = len + addr1 + addr2 + typ

  local data_tbl = {}

  for s in sdata:gmatch('%x%x') do
    local n = tonumber(s, 16)
    compl = compl + n
    table.insert(data_tbl, n)
  end

  if (crc + compl) % 0x100 ~= 0 then
    return nil, 'Checksum mismatch in line' .. line
  end

  if len ~= #data_tbl then
    return nil, 'Data length mismatch in line ' .. line
  end

  return {
    len = len,
    addr = addr1 * 256 + addr2,
    typ = typ,
    crc = crc,
    data = data_tbl,
  }
end

  -----------------------------------------------------------------------------

-- Convert an Intel HEX file into a binary file.
-- Return:
--   true on success,
--   false, "error message" on error.
function ihex_to_bin(ihex_filename, bin_filename)
  local ihex, err = io.open(ihex_filename, 'r')

  if not ihex then
    return false, 'Couldn\'t open input file for reading: ' .. err
  end

  local ok = true
  local seg = 0
  local upper16 = 0
  --[[
    Intel HEX basically represents data as a bunch of records mapped onto
    a 32-bit address space. We store the mapping in a table, and as we
    populate the table, we determine the starting and ending addresses, so we
    can extract the data later on.
  ]]
  local bdata = {}
  local bstart = 0xffffffff
  local bend = 0

  for line in ihex:lines() do
    local rec
    rec, err = parse_line(line)
    if rec then
      if rec.typ == HEX_REC_DATA then
        local ofs = upper16 * 65536 + seg * 16 + rec.addr
        for i = 1, rec.len do
          bdata[ofs + i - 1] = rec.data[i]
        end
        if ofs < bstart then
          bstart = ofs
        end
        ofs = ofs + rec.len
        if ofs > bend then
          bend = ofs
        end
      elseif rec.typ == HEX_REC_EXT_SEG_ADDR then
        seg = rec.data[1] * 256 + rec.data[2]
      elseif rec.typ == HEX_REC_EXT_LIN_ADDR then
        upper16 = rec.data[1] * 256 + rec.data[2]
      elseif rec.typ == HEX_REC_EOF then
        break
      elseif rec.typ == HEX_REC_START_SEG_ADDR then
        -- 8086 CS:IP entry point - ignore
      elseif rec.typ == HEX_REC_START_LIN_ADDR then
        -- x86 EIP entry point - ignore
      else
        -- can't happen (see parse_line)
        ok, err = false, 'Unknown record type in HEX file'
        break
      end
    else
      ok = false
      break
    end
  end

  ihex:close()

  if not ok then
    return ok, err
  end

  local bin, err = io.open(bin_filename, 'wb')

  if not bin then
    return false, 'Couldn\'t open output file for writing: ' .. err
  end

  -- bstart now contains the address of the first byte
  -- in the image, bend the address of the byte past
  -- the last 

  local p = 0

  while p < bend do
    local b = bdata[p] or filler
    -- FIXME writing by the byte; can we optimize this somehow?
    ok, err = bin:write(string.char(b))
    if type(ok) ~= 'boolean' then
      ok = ok ~= nil
    end
    if not ok then
      break
    end
    p = p + 1
  end

  bin:close()

  if not ok then
    os.remove(bin_filename)
  end

  return ok, err
end

  -----------------------------------------------------------------------------

local function div(x, y)
  local ret = math.modf(x / y)
  return ret
end

local function write_rec(f, rec)
  rec.len = #rec.data

  local addr1 = div(rec.addr, 256)
  local addr2 = rec.addr % 256
  local crc = rec.len + rec.typ + addr1 + addr2

  local dat = ''
  for i = 1, rec.len do
    crc = crc + rec.data[i]
    dat = dat .. sprintf('%02X', rec.data[i])
  end

  crc = 0 - crc

  local rec_str = sprintf(':%02X%02X%02X%02X%s%02X\n',
    rec.len, addr1, addr2, rec.typ, dat, math.modf(crc, 256) % 256)

  local ok, err = f:write(rec_str)
  if type(ok) ~= 'boolean' then
    ok = ok ~= nil
  end
  return ok, err
end

  -----------------------------------------------------------------------------

-- Convert a binary file into an Intel HEX file. The optional address parameter
-- determines the starting address of the data. If omitted, assume 0 as default
-- value.
-- Return:
--   true on success,
--   false, "error message" on error.
function bin_to_ihex(bin_filename, ihex_filename, address)
  local bin, err = io.open(bin_filename, 'rb')

  if not bin then
    return false, 'Couldn\'t open input file for reading: ' .. err
  end

  local ihex, err = io.open(ihex_filename, 'w')

  if not ihex then
    bin:close()
    return false, 'Couldn\'t open output file for writing: ' .. err
  end

  address = address or 0
  local HEX_REC_SIZE = 16

  local ok, upper16 = true, math.modf(address / 65536)
  local prev_upper16 = upper16 - 1 -- XXX these must differ on entry to the loop

  while true do

    if upper16 ~= prev_upper16 then
      prev_upper16 = upper16

      ok, err = write_rec(ihex,
        {
          typ = HEX_REC_EXT_LIN_ADDR,
          addr = 0,
          data = { div(upper16, 256), upper16 % 256 }
        }
      )

      if not ok then
        break
      end
    end

    local data, err = bin:read(HEX_REC_SIZE)

    if not data then
      if err then
        ok = false
      end
      break
    end

    ok, err = write_rec(ihex,
      {
        typ = HEX_REC_DATA,
        addr = address % 65536,
        data = { data:byte(1, #data) }
      }
    )

    if not ok then
      break
    end

    address = address + #data
    upper16 = div(address, 65536)
  end

  ok, err = write_rec(ihex,
    {
      typ = HEX_REC_EOF,
      addr = 0,
      data = {},
    }
  )

  ihex:close()
  bin:close()

  if not ok then
    os.remove(ihex_filename)
  end

  return ok, err
end

  -----------------------------------------------------------------------------

-- TEST $ lua ihex.lua {hex2bin|bin2hex} <inputfile> <outputfile> 

  local in_main = not pcall(debug.getlocal, 4, 1)

  if in_main then
    local ok = false
    local err = 'Invalid parameter(s)\n'..
      'Usage:\n\t' .. arg[0] .. ' {hex2bin|bin2hex} <inputfile> <outputfile>'

    if arg[1] and arg[2] and arg[3] then
      if arg[1] == 'hex2bin' then
        ok, err = ihex_to_bin(arg[2], arg[3])
      elseif arg[1] == 'bin2hex' then
        ok, err = bin_to_ihex(arg[2], arg[3])
      end
    end

    if not ok then
      print('*** ERROR: ' .. err)
    end
  end


