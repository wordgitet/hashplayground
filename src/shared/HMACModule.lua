--!strict
--!native
-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- HMAC is shared plumbing for PBKDF2 and future keyed digest experiments.

local byte = string.byte
local char = string.char
local rep = string.rep
local concat = table.concat

local function require_digest_module(digest_module)
	if type(digest_module) ~= "table" then
		error("HMAC digest module must be a table", 2)
	end

	local digest_bytes = digest_module.digest_bytes
	if type(digest_bytes) ~= "function" then
		error("HMAC digest module must expose digest_bytes(message)", 2)
	end

	local block_size = digest_module.block_size
	if type(block_size) ~= "number" or block_size <= 0 then
		error("HMAC digest module must expose a positive block_size", 2)
	end

	return digest_bytes, block_size
end

local function make_xor_pad(key_bytes, xor_value)
	local parts = table.create(#key_bytes)
	for i = 1, #key_bytes do
		parts[i] = char(bit32.bxor(byte(key_bytes, i), xor_value))
	end
	return concat(parts)
end

local function prepare(key, digest_module)
	if type(key) ~= "string" then
		error("HMAC key must be a string", 2)
	end

	local digest_bytes, block_size = require_digest_module(digest_module)
	if #key > block_size then
		key = digest_bytes(key)
	end

	if #key < block_size then
		key = key .. rep(char(0), block_size - #key)
	end

	return {
		digest_module = digest_module,
		inner_key = make_xor_pad(key, 0x36),
		outer_key = make_xor_pad(key, 0x5c),
		block_size = block_size,
	}
end

local function digest(prepared, message)
	if type(message) ~= "string" then
		error("HMAC message must be a string", 2)
	end

	if type(prepared) ~= "table" or type(prepared.digest_module) ~= "table" then
		error("HMAC prepared context is invalid", 2)
	end

	local digest_module = prepared.digest_module
	local digest_bytes = digest_module.digest_bytes
	local inner = digest_bytes(prepared.inner_key .. message)
	return digest_bytes(prepared.outer_key .. inner)
end

local function hex(prepared, message)
	local raw = digest(prepared, message)
	local parts = table.create(#raw)
	for i = 1, #raw do
		parts[i] = string.format("%02x", byte(raw, i))
	end
	return concat(parts)
end

local function one_shot(key, message, digest_module)
	return hex(prepare(key, digest_module), message)
end

return {
	prepare = prepare,
	digest = digest,
	hex = hex,
	hmac = one_shot,
	hmac_hex = one_shot,
}
