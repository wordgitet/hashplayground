--!strict
--!native
-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- SHA-1 currently delegates to Roblox's EncodingService when the engine exposes it.

local byte = string.byte
local char = string.char
local concat = table.concat

local encoding_service = nil
local sha1_algorithm = nil

do
	local ok_service, service = pcall(game.GetService, game, "EncodingService")
	if ok_service then
		encoding_service = service
	end

	local ok_algo, algo = pcall(function()
		return Enum.HashAlgorithm.Sha1
	end)
	if ok_algo then
		sha1_algorithm = algo
	end
end

local function bytes_to_hex(raw_bytes)
	local hex_parts = table.create(#raw_bytes)
	for i = 1, #raw_bytes do
		hex_parts[i] = string.format("%02x", byte(raw_bytes, i))
	end
	return concat(hex_parts)
end

local function hex_to_bytes(hex_digest)
	if #hex_digest % 2 ~= 0 or not hex_digest:match("^[0-9a-fA-F]+$") then
		error("SHA-1 native hash returned an invalid hex digest", 2)
	end

	local out = table.create(#hex_digest // 2)
	for i = 1, #hex_digest, 2 do
		out[#out + 1] = char(tonumber(hex_digest:sub(i, i + 1), 16) :: number)
	end
	return concat(out)
end

local function compute_native_hash(message)
	local service = encoding_service
	local algorithm = sha1_algorithm
	if not service or not algorithm then
		error("SHA-1 requires EncodingService support", 2)
	end

	return service:ComputeStringHash(message, algorithm)
end

local function normalize_native_bytes(native_hash)
	if type(native_hash) ~= "string" then
		error("SHA-1 native hash returned a non-string result", 2)
	end

	if #native_hash == 20 then
		return native_hash
	end

	local lowered = string.lower(native_hash)
	if #lowered == 40 and lowered:match("^[0-9a-f]+$") then
		return hex_to_bytes(lowered)
	end

	error("SHA-1 native hash returned an unsupported format", 2)
end

local function sha1_bytes(message)
	return normalize_native_bytes(compute_native_hash(message))
end

local function sha1(message)
	return bytes_to_hex(sha1_bytes(message))
end

return {
	hash = sha1,
	sha1 = sha1,
	sha1_bytes = sha1_bytes,
	digest_bytes = sha1_bytes,
	block_size = 64,
	digest_size = 20,
	algorithms = {
		sha1 = sha1,
	},
}
