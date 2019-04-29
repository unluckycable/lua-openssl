#!/usr/bin/lua

--[[

local openssl = require("openssl")

local key = openssl.gen_rsa_key(1024)
print(key)

local csr = openssl.gen_csr(key)
print(csr)

local crt = openssl.gen_crt(key)
print(crt)

local crt1 = openssl.csr_crt(key, crt, csr)
print(crt1)

# openssl x509 -text -noout -in ./csr
]]--

-- local openssl = require("openssl.core")

local openssl = require("core")

local M = {
  --gen_rsa_key = openssl.gen_rsa_key,
  --gen_csr     = openssl.gen_csr,
  --gen_crt     = openssl.gen_crt,
  init_crypto = openssl.init_crypto,
  csr_crt     = openssl.csr_crt,
}

return M
