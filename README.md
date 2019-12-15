# TLS Cipher Counter

## Running

    tshark -X lua_script:tls-cipher-counter.lua -q -r <packet-capture-file>

## Regenerating Ciphers

    ./ciphersuites.rb
