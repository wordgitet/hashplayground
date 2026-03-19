--!strict
--!native
-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- SHA-1 currently delegates to Roblox's EncodingService when the engine exposes it.

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

local function normalize_native_hash(native_hash)
	if type(native_hash) ~= "string" then
		return tostring(native_hash)
	end

	local lowered = string.lower(native_hash)
	if #lowered == 40 and lowered:match("^[0-9a-f]+$") then
		return lowered
	end

	if #native_hash == 20 then
		local hex_parts = table.create(#native_hash)
		for i = 1, #native_hash do
			hex_parts[i] = string.format("%02x", string.byte(native_hash, i))
		end
		return table.concat(hex_parts)
	end

	return native_hash
end

local function sha1(message)
	if not encoding_service or not sha1_algorithm then
		error("SHA-1 requires EncodingService support", 2)
	end

	local ok, native_hash = pcall(function()
		return encoding_service:ComputeStringHash(message, sha1_algorithm)
	end)
	if not ok then
		error(native_hash, 2)
	end

	return normalize_native_hash(native_hash)
end

return {
	hash = sha1,
	sha1 = sha1,
	algorithms = {
		sha1 = sha1,
	},
}
