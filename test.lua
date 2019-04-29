#!/usr/bin/lua
--[[

  make clean && make && ./test.lua ; valgrind -v  --leak-check=full --show-leak-kinds=all ./test.lua

]]--



local openssl = require("openssl")

while 1 do
 local key = openssl.gen_rsa_key(1024)
 local csr = openssl.gen_csr(key)
 local crt = openssl.gen_crt(key)
 local crt2 = openssl.csr_crt(key, crt, csr)
end


 local key = openssl.gen_rsa_key(1024)
 print(key)
 local csr = openssl.gen_csr(key)
 print(csr)
 local crt = openssl.gen_crt(key)
 print(crt)
 local crt1 = openssl.csr_crt(key, crt, csr)
 print(crt1)
