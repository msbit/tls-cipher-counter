local client_ciphers = {}
local server_ciphers = {}

local major_version = tonumber(get_version():match("(%d+)%.*"))
local protocol = "tls"
if major_version < 3 then
  protocol = "ssl"
end

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

local function increment_key(table, key)
  if type(table[key]) == 'nil' then
    table[key] = 0
  end
  table[key] = table[key] + 1
end

local function init_client_listener()
  local cipher_suites_length = Field.new(protocol .. ".handshake.cipher_suites_length")
  local client_tap = Listener.new(protocol, protocol .. ".handshake.type == 1")

  function client_tap.reset()
    client_ciphers = {}
  end

  function client_tap.packet(pinfo, tvb, client_tapinfo)
    local count_length_offset = -cipher_suites_length()
    local count = tvb:range(count_length_offset, 0x2):uint() / 2
    local cipher_index = count_length_offset + 2
    for i = 0, count - 1 do
      local id = tostring(tvb:range(cipher_index + (i * 2), 0x2):bytes())
      increment_key(client_ciphers, id)
    end
  end

  function client_tap.draw()
    print("CLIENT CIPHERS\n")

    print_ciphers(client_ciphers)
  end
end

local function init_server_listener()
  local ciphersuite = Field.new(protocol .. ".handshake.ciphersuite")
  local server_tap = Listener.new(protocol, protocol .. ".handshake.type == 2")

  function server_tap.reset()
    server_ciphers = {}
  end

  function server_tap.packet(pinfo, tvb, client_tapinfo)
    local result = ciphersuite()
    local id = tostring(result.range:bytes())
    increment_key(server_ciphers, id)
  end

  function server_tap.draw()
    print("SERVER CIPHERS\n")

    print_ciphers(server_ciphers)
  end
end

init_client_listener()
init_server_listener()
