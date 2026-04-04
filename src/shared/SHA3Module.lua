--!strict
--!native
-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- SHA-3 is implemented directly in Luau using the Keccak-f[1600] permutation.
-- The fixed-length SHA3-* variants all reuse the same sponge core with different rates and output lengths.

local band = bit32.band
local bor = bit32.bor
local bxor = bit32.bxor
local bnot = bit32.bnot
local rshift = bit32.rshift
local lshift = bit32.lshift
local byte = string.byte
local concat = table.concat
local rep = string.rep
local unpack = table.unpack

local MASK32 = 0xFFFFFFFF
local SHA3_SUFFIX = 0x06
local SHAKE_SUFFIX = 0x1F
local CSHAKE_SUFFIX = 0x04

local RHO = {
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

local RC_LO = {
	0x00000001, 0x00008082, 0x0000808A, 0x80008000,
	0x0000808B, 0x80000001, 0x80008081, 0x00008009,
	0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
	0x8000808B, 0x0000008B, 0x00008089, 0x00008003,
	0x00008002, 0x00000080, 0x0000800A, 0x8000000A,
	0x80008081, 0x00008080, 0x80000001, 0x80008008,
}

local RC_HI = {
	0x00000000, 0x00000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x80000000, 0x80000000, 0x80000000,
	0x80000000, 0x80000000, 0x00000000, 0x80000000,
	0x80000000, 0x80000000, 0x00000000, 0x80000000,
}

local HEX = table.create(256)
for value = 0, 255 do
	HEX[value] = string.format("%02x", value)
end

local function bytes_to_string(bytes)
	if #bytes == 0 then
		return ""
	end

	local parts = table.create(math.ceil(#bytes / 96))
	local part_index = 1
	for start_index = 1, #bytes, 96 do
		local finish_index = math.min(start_index + 95, #bytes)
		parts[part_index] = string.char(unpack(bytes, start_index, finish_index))
		part_index += 1
	end
	return concat(parts)
end

local function left_encode(value)
	if type(value) ~= "number" or value ~= math.floor(value) or value < 0 then
		error("SP800-185 integer must be a non-negative integer", 2)
	end

	local body = table.create(9)
	local body_len = 0
	repeat
		body_len += 1
		body[body_len] = value % 256
		value = math.floor(value / 256)
	until value == 0

	local out = table.create(body_len + 1)
	out[1] = body_len
	for index = 1, body_len do
		out[index + 1] = body[body_len - index + 1]
	end
	return bytes_to_string(out)
end

local function right_encode(value)
	if type(value) ~= "number" or value ~= math.floor(value) or value < 0 then
		error("SP800-185 integer must be a non-negative integer", 2)
	end

	local body = table.create(9)
	local body_len = 0
	repeat
		body_len += 1
		body[body_len] = value % 256
		value = math.floor(value / 256)
	until value == 0

	local out = table.create(body_len + 1)
	for index = 1, body_len do
		out[index] = body[body_len - index + 1]
	end
	out[body_len + 1] = body_len
	return bytes_to_string(out)
end

local function encode_string(text)
	if type(text) ~= "string" then
		error("SP800-185 string input must be a string", 2)
	end
	return left_encode(#text * 8) .. text
end

local function bytepad(text, width)
	if type(text) ~= "string" then
		error("SP800-185 bytepad input must be a string", 2)
	end
	if type(width) ~= "number" or width ~= math.floor(width) or width <= 0 then
		error("SP800-185 bytepad width must be a positive integer", 2)
	end

	local encoded = left_encode(width) .. text
	local pad_len = (width - (#encoded % width)) % width
	if pad_len == 0 then
		return encoded
	end
	return encoded .. rep("\0", pad_len)
end

local function u32(value)
	return band(value, MASK32)
end

local function rotl64(lo, hi, shift)
	shift %= 64
	if shift == 0 then
		return lo, hi
	elseif shift < 32 then
		return u32(bor(lshift(lo, shift), rshift(hi, 32 - shift))), u32(bor(lshift(hi, shift), rshift(lo, 32 - shift)))
	elseif shift == 32 then
		return hi, lo
	else
		local s = shift - 32
		return u32(bor(lshift(hi, s), rshift(lo, 32 - s))), u32(bor(lshift(lo, s), rshift(hi, 32 - s)))
	end
end

local function read_lane_le(text, index)
	local b1, b2, b3, b4, b5, b6, b7, b8 = byte(text, index, index + 7)
	return u32(bor(b1 or 0, lshift(b2 or 0, 8), lshift(b3 or 0, 16), lshift(b4 or 0, 24))),
		u32(bor(b5 or 0, lshift(b6 or 0, 8), lshift(b7 or 0, 16), lshift(b8 or 0, 24)))
end

local function read_lane_le_from_bytes(bytes, index)
	return u32(bor(bytes[index] or 0, lshift(bytes[index + 1] or 0, 8), lshift(bytes[index + 2] or 0, 16), lshift(bytes[index + 3] or 0, 24))),
		u32(bor(bytes[index + 4] or 0, lshift(bytes[index + 5] or 0, 8), lshift(bytes[index + 6] or 0, 16), lshift(bytes[index + 7] or 0, 24)))
end

local function absorb_block_from_string(state_lo, state_hi, message, start_index, rate_words)
	local word_start = start_index
	for lane_index = 1, rate_words do
		local lo, hi = read_lane_le(message, word_start)
		state_lo[lane_index] = bxor(state_lo[lane_index], lo)
		state_hi[lane_index] = bxor(state_hi[lane_index], hi)
		word_start += 8
	end
end

local function absorb_block_from_bytes(state_lo, state_hi, block, rate_words)
	local word_start = 1
	for lane_index = 1, rate_words do
		local lo, hi = read_lane_le_from_bytes(block, word_start)
		state_lo[lane_index] = bxor(state_lo[lane_index], lo)
		state_hi[lane_index] = bxor(state_hi[lane_index], hi)
		word_start += 8
	end
end

local function keccak_f1600(state_lo, state_hi)
	local c_lo = table.create(5, 0)
	local c_hi = table.create(5, 0)
	local d_lo = table.create(5, 0)
	local d_hi = table.create(5, 0)
	local b_lo = table.create(25, 0)
	local b_hi = table.create(25, 0)

	for round_index = 1, 24 do
		for x = 0, 4 do
			local index0 = x + 1
			local index1 = x + 6
			local index2 = x + 11
			local index3 = x + 16
			local index4 = x + 21
			c_lo[x + 1] = bxor(state_lo[index0], state_lo[index1], state_lo[index2], state_lo[index3], state_lo[index4])
			c_hi[x + 1] = bxor(state_hi[index0], state_hi[index1], state_hi[index2], state_hi[index3], state_hi[index4])
		end

		for x = 0, 4 do
			local left = ((x + 4) % 5) + 1
			local right = ((x + 1) % 5) + 1
			local rot_lo, rot_hi = rotl64(c_lo[right], c_hi[right], 1)
			d_lo[x + 1] = bxor(c_lo[left], rot_lo)
			d_hi[x + 1] = bxor(c_hi[left], rot_hi)
		end

		for y = 0, 4 do
			local row = y * 5
			for x = 0, 4 do
				local index = row + x + 1
				state_lo[index] = bxor(state_lo[index], d_lo[x + 1])
				state_hi[index] = bxor(state_hi[index], d_hi[x + 1])
			end
		end

		for y = 0, 4 do
			local row = y * 5
			for x = 0, 4 do
				local index = row + x + 1
				local rot_lo, rot_hi = rotl64(state_lo[index], state_hi[index], RHO[index])
				local dest_x = y
				local dest_y = (2 * x + 3 * y) % 5
				local dest_index = (dest_y * 5) + dest_x + 1
				b_lo[dest_index] = rot_lo
				b_hi[dest_index] = rot_hi
			end
		end

		for y = 0, 4 do
			local row = y * 5
			for x = 0, 4 do
				local index = row + x + 1
				local next_index = row + ((x + 1) % 5) + 1
				local next2_index = row + ((x + 2) % 5) + 1
				state_lo[index] = bxor(b_lo[index], band(bnot(b_lo[next_index]), b_lo[next2_index]))
				state_hi[index] = bxor(b_hi[index], band(bnot(b_hi[next_index]), b_hi[next2_index]))
			end
		end

		state_lo[1] = bxor(state_lo[1], RC_LO[round_index])
		state_hi[1] = bxor(state_hi[1], RC_HI[round_index])
	end
end

local function squeeze_hex(state_lo, state_hi, rate_words, output_bytes)
	local parts = table.create(output_bytes)
	local written = 0

	while written < output_bytes do
		for lane_index = 1, rate_words do
			if written >= output_bytes then
				break
			end

			local lo = state_lo[lane_index]
			local hi = state_hi[lane_index]
			local take = math.min(8, output_bytes - written)

			if take >= 1 then parts[written + 1] = HEX[band(lo, 0xFF)] end
			if take >= 2 then parts[written + 2] = HEX[band(rshift(lo, 8), 0xFF)] end
			if take >= 3 then parts[written + 3] = HEX[band(rshift(lo, 16), 0xFF)] end
			if take >= 4 then parts[written + 4] = HEX[band(rshift(lo, 24), 0xFF)] end
			if take >= 5 then parts[written + 5] = HEX[band(hi, 0xFF)] end
			if take >= 6 then parts[written + 6] = HEX[band(rshift(hi, 8), 0xFF)] end
			if take >= 7 then parts[written + 7] = HEX[band(rshift(hi, 16), 0xFF)] end
			if take >= 8 then parts[written + 8] = HEX[band(rshift(hi, 24), 0xFF)] end

			written += take
		end

		if written < output_bytes then
			keccak_f1600(state_lo, state_hi)
		end
	end

	return concat(parts)
end

local function squeeze_bytes(state_lo, state_hi, rate_words, output_bytes)
	local parts = table.create(math.ceil(output_bytes / 8))
	local written = 0
	local part_index = 1

	while written < output_bytes do
		for lane_index = 1, rate_words do
			if written >= output_bytes then
				break
			end

			local lo = state_lo[lane_index]
			local hi = state_hi[lane_index]
			local chunk = string.char(
				band(lo, 0xFF),
				band(rshift(lo, 8), 0xFF),
				band(rshift(lo, 16), 0xFF),
				band(rshift(lo, 24), 0xFF),
				band(hi, 0xFF),
				band(rshift(hi, 8), 0xFF),
				band(rshift(hi, 16), 0xFF),
				band(rshift(hi, 24), 0xFF)
			)
			local remaining = output_bytes - written
			if remaining < 8 then
				chunk = string.sub(chunk, 1, remaining)
			end
			parts[part_index] = chunk
			written += #chunk
			part_index += 1
		end

		if written < output_bytes then
			keccak_f1600(state_lo, state_hi)
		end
	end

	return concat(parts)
end

local function absorb_sponge(message, rate_bytes, suffix)
	if type(message) ~= "string" then
		error("SHA-3 input must be a string", 2)
	end

	local state_lo = table.create(25, 0)
	local state_hi = table.create(25, 0)
	local rate_words = rate_bytes // 8
	local message_len = #message
	local full_blocks = message_len // rate_bytes
	local block_start = 1

	for _ = 1, full_blocks do
		absorb_block_from_string(state_lo, state_hi, message, block_start, rate_words)
		keccak_f1600(state_lo, state_hi)
		block_start += rate_bytes
	end

	local remainder = message_len % rate_bytes
	local block = table.create(rate_bytes, 0)
	for i = 1, remainder do
		block[i] = byte(message, block_start + i - 1) :: number
	end
	block[remainder + 1] = bxor(block[remainder + 1] or 0, suffix)
	block[rate_bytes] = bxor(block[rate_bytes] or 0, 0x80)
	absorb_block_from_bytes(state_lo, state_hi, block, rate_words)
	keccak_f1600(state_lo, state_hi)

	return state_lo, state_hi, rate_words
end

local function sha3_hex(message, rate_bytes, output_bytes)
	local state_lo, state_hi, rate_words = absorb_sponge(message, rate_bytes, SHA3_SUFFIX)
	return squeeze_hex(state_lo, state_hi, rate_words, output_bytes)
end

local function sha3_bytes(message, rate_bytes, output_bytes)
	local state_lo, state_hi, rate_words = absorb_sponge(message, rate_bytes, SHA3_SUFFIX)
	return squeeze_bytes(state_lo, state_hi, rate_words, output_bytes)
end

local function shake_hex(message, rate_bytes, output_bytes)
	if type(output_bytes) ~= "number" or output_bytes ~= math.floor(output_bytes) or output_bytes <= 0 then
		error("SHAKE output length must be a positive integer", 2)
	end

	local state_lo, state_hi, rate_words = absorb_sponge(message, rate_bytes, SHAKE_SUFFIX)
	return squeeze_hex(state_lo, state_hi, rate_words, output_bytes)
end

local function shake_bytes(message, rate_bytes, output_bytes)
	if type(output_bytes) ~= "number" or output_bytes ~= math.floor(output_bytes) or output_bytes <= 0 then
		error("SHAKE output length must be a positive integer", 2)
	end

	local state_lo, state_hi, rate_words = absorb_sponge(message, rate_bytes, SHAKE_SUFFIX)
	return squeeze_bytes(state_lo, state_hi, rate_words, output_bytes)
end

local function cshake_hex(message, rate_bytes, output_bytes, function_name, customization)
	if type(function_name) ~= "string" then
		error("cSHAKE function name must be a string", 2)
	end
	if type(customization) ~= "string" then
		error("cSHAKE customization must be a string", 2)
	end
	if function_name == "" and customization == "" then
		return shake_hex(message, rate_bytes, output_bytes)
	end

	local prefix = bytepad(encode_string(function_name) .. encode_string(customization), rate_bytes)
	local state_lo, state_hi, rate_words = absorb_sponge(prefix .. message, rate_bytes, CSHAKE_SUFFIX)
	return squeeze_hex(state_lo, state_hi, rate_words, output_bytes)
end

local function cshake_bytes(message, rate_bytes, output_bytes, function_name, customization)
	if type(function_name) ~= "string" then
		error("cSHAKE function name must be a string", 2)
	end
	if type(customization) ~= "string" then
		error("cSHAKE customization must be a string", 2)
	end
	if function_name == "" and customization == "" then
		return shake_bytes(message, rate_bytes, output_bytes)
	end

	local prefix = bytepad(encode_string(function_name) .. encode_string(customization), rate_bytes)
	local state_lo, state_hi, rate_words = absorb_sponge(prefix .. message, rate_bytes, CSHAKE_SUFFIX)
	return squeeze_bytes(state_lo, state_hi, rate_words, output_bytes)
end

local function sha3_224_hex(message)
	return sha3_hex(message, 144, 28)
end

local function sha3_256_hex(message)
	return sha3_hex(message, 136, 32)
end

local function sha3_384_hex(message)
	return sha3_hex(message, 104, 48)
end

local function sha3_512_hex(message)
	return sha3_hex(message, 72, 64)
end

local function sha3_224_bytes(message)
	return sha3_bytes(message, 144, 28)
end

local function sha3_256_bytes(message)
	return sha3_bytes(message, 136, 32)
end

local function sha3_384_bytes(message)
	return sha3_bytes(message, 104, 48)
end

local function sha3_512_bytes(message)
	return sha3_bytes(message, 72, 64)
end

local function shake128_hex(message, output_bytes)
	return shake_hex(message, 168, output_bytes)
end

local function shake256_hex(message, output_bytes)
	return shake_hex(message, 136, output_bytes)
end

local function shake128_bytes(message, output_bytes)
	return shake_bytes(message, 168, output_bytes)
end

local function shake256_bytes(message, output_bytes)
	return shake_bytes(message, 136, output_bytes)
end

local function cshake128_hex(message, output_bytes, function_name, customization)
	return cshake_hex(message, 168, output_bytes, function_name or "", customization or "")
end

local function cshake256_hex(message, output_bytes, function_name, customization)
	return cshake_hex(message, 136, output_bytes, function_name or "", customization or "")
end

local function cshake128_bytes(message, output_bytes, function_name, customization)
	return cshake_bytes(message, 168, output_bytes, function_name or "", customization or "")
end

local function cshake256_bytes(message, output_bytes, function_name, customization)
	return cshake_bytes(message, 136, output_bytes, function_name or "", customization or "")
end

local function kmac_hex(rate_bytes, key, message, output_bytes, customization)
	if type(key) ~= "string" then
		error("KMAC key must be a string", 2)
	end
	if type(message) ~= "string" then
		error("KMAC message must be a string", 2)
	end
	if type(customization) ~= "string" then
		error("KMAC customization must be a string", 2)
	end
	if type(output_bytes) ~= "number" or output_bytes ~= math.floor(output_bytes) or output_bytes <= 0 then
		error("KMAC output length must be a positive integer", 2)
	end

	local encoded_input = bytepad(encode_string(key), rate_bytes) .. message .. right_encode(output_bytes * 8)
	return cshake_hex(encoded_input, rate_bytes, output_bytes, "KMAC", customization)
end

local function kmac_bytes(rate_bytes, key, message, output_bytes, customization)
	if type(key) ~= "string" then
		error("KMAC key must be a string", 2)
	end
	if type(message) ~= "string" then
		error("KMAC message must be a string", 2)
	end
	if type(customization) ~= "string" then
		error("KMAC customization must be a string", 2)
	end
	if type(output_bytes) ~= "number" or output_bytes ~= math.floor(output_bytes) or output_bytes <= 0 then
		error("KMAC output length must be a positive integer", 2)
	end

	local encoded_input = bytepad(encode_string(key), rate_bytes) .. message .. right_encode(output_bytes * 8)
	return cshake_bytes(encoded_input, rate_bytes, output_bytes, "KMAC", customization)
end

local function kmac128_hex(key, message, output_bytes, customization)
	return kmac_hex(168, key, message, output_bytes, customization or "")
end

local function kmac256_hex(key, message, output_bytes, customization)
	return kmac_hex(136, key, message, output_bytes, customization or "")
end

local function kmac128_bytes(key, message, output_bytes, customization)
	return kmac_bytes(168, key, message, output_bytes, customization or "")
end

local function kmac256_bytes(key, message, output_bytes, customization)
	return kmac_bytes(136, key, message, output_bytes, customization or "")
end

local algorithms = {
	sha3_224 = sha3_224_hex,
	sha3_256 = sha3_256_hex,
	sha3_384 = sha3_384_hex,
	sha3_512 = sha3_512_hex,
	shake128 = function(message)
		return shake128_hex(message, 32)
	end,
	shake256 = function(message)
		return shake256_hex(message, 64)
	end,
	cshake128 = function(message)
		return cshake128_hex(message, 32, "", "")
	end,
	cshake256 = function(message)
		return cshake256_hex(message, 64, "", "")
	end,
}

return {
	hash = sha3_256_hex,
	sha3 = sha3_256_hex,
	sha3_224 = sha3_224_hex,
	sha3_256 = sha3_256_hex,
	sha3_384 = sha3_384_hex,
	sha3_512 = sha3_512_hex,
	sha3_224_bytes = sha3_224_bytes,
	sha3_256_bytes = sha3_256_bytes,
	sha3_384_bytes = sha3_384_bytes,
	sha3_512_bytes = sha3_512_bytes,
	shake128 = shake128_hex,
	shake256 = shake256_hex,
	shake128_bytes = shake128_bytes,
	shake256_bytes = shake256_bytes,
	cshake128 = cshake128_hex,
	cshake256 = cshake256_hex,
	cshake128_bytes = cshake128_bytes,
	cshake256_bytes = cshake256_bytes,
	kmac128 = kmac128_hex,
	kmac256 = kmac256_hex,
	kmac128_bytes = kmac128_bytes,
	kmac256_bytes = kmac256_bytes,
	algorithms = algorithms,
}
