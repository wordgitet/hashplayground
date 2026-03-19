--!strict
--!native
-- SPDX-License-Identifier: Apache-2.0
-- Hash Playground Rojo export.
-- Ported from the OpenSSL PBKDF2 implementation.
-- PBKDF2 builds on HMAC plus the SHA modules so the GUI can offer a separate key-derivation mode.

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local HMACModule = require(ReplicatedStorage:WaitForChild("HMACModule"))
local SHA256Module = require(ReplicatedStorage:WaitForChild("SHA256Module"))
local SHA512Module = require(ReplicatedStorage:WaitForChild("SHA512Module"))

local band = bit32.band
local bxor = bit32.bxor
local byte = string.byte
local char = string.char
local concat = table.concat
local floor = math.floor

local DIGESTS = {
	sha256 = SHA256Module,
	sha512 = SHA512Module,
}

local function bytes_to_hex(raw_bytes)
	local hex_parts = table.create(#raw_bytes)
	for i = 1, #raw_bytes do
		hex_parts[i] = string.format("%02x", byte(raw_bytes, i))
	end
	return concat(hex_parts)
end

local function xor_bytes(left_bytes, right_bytes)
	if #left_bytes ~= #right_bytes then
		error("PBKDF2 xor inputs must have the same length", 2)
	end

	local out = table.create(#left_bytes)
	for i = 1, #left_bytes do
		out[i] = char(bxor(byte(left_bytes, i), byte(right_bytes, i)))
	end
	return concat(out)
end

local function int32_be(value)
	return char(
		band(bit32.rshift(value, 24), 0xFF),
		band(bit32.rshift(value, 16), 0xFF),
		band(bit32.rshift(value, 8), 0xFF),
		band(value, 0xFF)
	)
end

local function resolve_digest_module(digest_name)
	if type(digest_name) == "table" then
		if type(digest_name.digest_bytes) ~= "function" then
			error("PBKDF2 digest module must expose digest_bytes(message)", 2)
		end
		return digest_name
	end

	if type(digest_name) ~= "string" then
		error("PBKDF2 digest must be a string or digest module", 2)
	end

	local digest_module = DIGESTS[string.lower(digest_name)]
	if digest_module == nil then
		error("PBKDF2 digest must be sha256 or sha512", 2)
	end

	return digest_module
end

local function require_positive_integer(value, field_name)
	if type(value) ~= "number" or value ~= floor(value) or value <= 0 then
		error(field_name .. " must be a positive integer", 2)
	end
	return value
end

local function derive_bytes(password, salt, iterations, dk_len, digest_name)
	if type(password) ~= "string" then
		error("PBKDF2 password must be a string", 2)
	end
	if type(salt) ~= "string" then
		error("PBKDF2 salt must be a string", 2)
	end

	iterations = require_positive_integer(iterations, "PBKDF2 iterations")
	dk_len = require_positive_integer(dk_len, "PBKDF2 derived key length")

	local digest_module = resolve_digest_module(digest_name)
	local digest_size = digest_module.digest_size
	if type(digest_size) ~= "number" or digest_size <= 0 then
		error("PBKDF2 digest module must expose digest_size", 2)
	end

	local prepared = HMACModule.prepare(password, digest_module)
	local block_count = math.ceil(dk_len / digest_size)
	local blocks = table.create(block_count)

	for block_index = 1, block_count do
		local u = HMACModule.digest(prepared, salt .. int32_be(block_index))
		local t = u

		for _ = 2, iterations do
			u = HMACModule.digest(prepared, u)
			t = xor_bytes(t, u)
		end

		blocks[block_index] = t
	end

	return (concat(blocks)):sub(1, dk_len)
end

local function derive_hex(password, salt, iterations, dk_len, digest_name)
	return bytes_to_hex(derive_bytes(password, salt, iterations, dk_len, digest_name))
end

local function pbkdf2_sha256(password, salt, iterations, dk_len)
	return derive_hex(password, salt, iterations, dk_len, "sha256")
end

local function pbkdf2_sha512(password, salt, iterations, dk_len)
	return derive_hex(password, salt, iterations, dk_len, "sha512")
end

local algorithms = {
	pbkdf2_sha256 = pbkdf2_sha256,
	pbkdf2_sha512 = pbkdf2_sha512,
}

return {
	derive = derive_hex,
	derive_hex = derive_hex,
	derive_bytes = derive_bytes,
	pbkdf2_sha256 = pbkdf2_sha256,
	pbkdf2_sha512 = pbkdf2_sha512,
	digests = DIGESTS,
	algorithms = algorithms,
}
