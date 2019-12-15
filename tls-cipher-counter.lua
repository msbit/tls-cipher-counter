local ciphers = {}

local function init_listener()
  local tap = Listener.new("frame", "ssl.handshake.type == 1")

  function tap.reset()
    ciphers = {}
  end

  function tap.packet(pinfo, tvb, tapinfo)
    local count = tvb:range(0x8e, 0x2):uint() / 2
    for i=0, count - 1 do
      local id = tostring(tvb:range(0x90 + (i * 2), 0x2):bytes())
      if type(ciphers[id]) == 'nil' then
        ciphers[id] = 0
      end
      ciphers[id] = ciphers[id] + 1
    end
  end

  function tap.draw()
    for id, count in pairs(ciphers) do
      print(id, count)
    end
  end
end

init_listener()
