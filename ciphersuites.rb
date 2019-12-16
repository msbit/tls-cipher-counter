#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'

require 'open-uri'

output = {
  '00FF' => 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'
}

open('https://ciphersuite.info/api/cs/') do |f|
  content = File.read(f)
  data = JSON.parse(content)

  data['ciphersuites'].each do |c|
    c.each do |k, v|
      bytes = [
        v['hex_byte_1'].delete_prefix('0x'),
        v['hex_byte_2'].delete_prefix('0x')
      ]
      output[bytes.join] = k
    end
  end
end

output = output.sort_by { |k, _| k }.to_h

File.open('ciphersuites.lua', 'w') do |file|
  file.write("ciphersuites = {\n")
  until output.empty?
    key, value = output.shift

    file.write("  [\"#{key}\"] = \"#{value}\"")
    file.write(',') unless output.empty?

    file.write("\n")
  end
  file.write("}\n")
end
