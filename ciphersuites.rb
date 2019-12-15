#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'

require 'open-uri'

output = {}

open('https://ciphersuite.info/api/cs/') do |f|
  content = File.read(f)
  data = JSON.parse(content)

  data['ciphersuites'].sort! do |a, b|
    a_bytes = [a.values.first['hex_byte_1'], a.values.first['hex_byte_2']]
    b_bytes = [b.values.first['hex_byte_1'], b.values.first['hex_byte_2']]
    a_bytes <=> b_bytes
  end

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
