#!/usr/bin/lua
--[[
  make clean && make && ./test.lua ; valgrind -v  --leak-check=full --show-leak-kinds=all ./test.lua

]]--

local openssl = require("openssl")

local infinitytest = function()
  while 1 do
    local key = openssl.gen_rsa_key(1024)
    local csr = openssl.gen_csr(key)
    local crt = openssl.gen_crt(key)
    local crt2 = openssl.csr_crt(key, crt, csr)
  end
end


local onetest = function()
  local key = openssl.gen_rsa_key(1024)
  print(key)
  local csr = openssl.gen_csr(key)
  print(csr)
  local crt = openssl.gen_crt(key)
  print(crt)
  local crt2 = openssl.csr_crt(key, crt, csr)
  print(crt2)
end


local test = function()
  local wfile = function(name, data)
    local f = io.open(name, "w+")
    f:write(data)
    f:close()
  end

  local key = openssl.gen_rsa_key(1024)
  if key then
    local fname = 'private.key'
    wfile(fname, key)
    os.execute('openssl rsa -text -noout -in ' .. fname)
  end

  local crt = openssl.gen_crt(key)
  if crt then
    local fname = 'private.crt'
    wfile(fname, crt)
    os.execute('openssl x509 -text -noout -in ' .. fname)
  end

  local csr = openssl.gen_csr(key)
  if csr then
    local fname = 'private.csr'
    wfile(fname, csr)
    os.execute('openssl req -text -noout -in ' .. fname)
  end

  local crt1 = openssl.csr_crt(key, crt, csr)
  if crt1 then
    local fname = 'public.crt'
    wfile(fname, crt1)
    os.execute('openssl x509 -text -noout -in ' .. fname)
  end
end


-- test()
onetest()
-- infinitytest()
