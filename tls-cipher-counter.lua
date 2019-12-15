local ciphers = {}

local function init_listener()
  local cipher_suites_length = Field.new("ssl.handshake.cipher_suites_length")
  local tap = Listener.new("ssl", "ssl.handshake.type == 1")

  function tap.reset()
    ciphers = {}
  end

  function tap.packet(pinfo, tvb, tapinfo)
    local count_length_offset = -cipher_suites_length()
    local count = tvb:range(count_length_offset, 0x2):uint() / 2
    local cipher_index = count_length_offset + 2
    for i = 0, count - 1 do
      local id = tostring(tvb:range(cipher_index + (i * 2), 0x2):bytes())
      if type(ciphers[id]) == 'nil' then
        ciphers[id] = 0
      end
      ciphers[id] = ciphers[id] + 1
    end
  end

  function tap.draw()
    require "ciphersuites"

    for id, count in pairs(ciphers) do
      if type(ciphersuites[id]) == 'nil' then
        print(id, count)
      else
        print(ciphersuites[id], count)
      end
    end
  end
end

init_listener()
