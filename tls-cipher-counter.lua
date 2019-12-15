local client_ciphers = {}
local server_ciphers = {}

local function print_ciphers(ciphers)
  require "ciphersuites"

  local cipher_ids = {}
  for k, _ in pairs(ciphersuites) do
    table.insert(cipher_ids, k)
  end
  table.sort(cipher_ids)

  for _, cipher_id in pairs(cipher_ids) do
    if type(ciphers[cipher_id]) ~= 'nil' then
      print(ciphersuites[cipher_id], ciphers[cipher_id])

      ciphers[cipher_id] = nil
    end
  end

  for id, count in pairs(ciphers) do
    print(id, count)
  end

  print()
end

local function init_client_listener()
  local cipher_suites_length = Field.new("ssl.handshake.cipher_suites_length")
  local client_tap = Listener.new("ssl", "ssl.handshake.type == 1")

  function client_tap.reset()
    client_ciphers = {}
  end

  function client_tap.packet(pinfo, tvb, client_tapinfo)
    local count_length_offset = -cipher_suites_length()
    local count = tvb:range(count_length_offset, 0x2):uint() / 2
    local cipher_index = count_length_offset + 2
    for i = 0, count - 1 do
      local id = tostring(tvb:range(cipher_index + (i * 2), 0x2):bytes())
      if type(client_ciphers[id]) == 'nil' then
        client_ciphers[id] = 0
      end
      client_ciphers[id] = client_ciphers[id] + 1
    end
  end

  function client_tap.draw()
    print("CLIENT CIPHERS\n")

    print_ciphers(client_ciphers)
  end
end

local function init_server_listener()
  local ciphersuite = Field.new("ssl.handshake.ciphersuite")
  local server_tap = Listener.new("ssl", "ssl.handshake.type == 2")

  function server_tap.reset()
    server_ciphers = {}
  end

  function server_tap.packet(pinfo, tvb, client_tapinfo)
    local result = ciphersuite()
    local id = tostring(result.range:bytes())
    if type(server_ciphers[id]) == 'nil' then
      server_ciphers[id] = 0
    end
    server_ciphers[id] = server_ciphers[id] + 1
  end

  function server_tap.draw()
    print("SERVER CIPHERS\n")

    print_ciphers(server_ciphers)
  end
end

init_client_listener()
init_server_listener()
