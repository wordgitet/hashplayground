--!strict
--!native
-- SPDX-License-Identifier: Apache-2.0
-- Hash Playground Rojo export.
-- Ported from the official BLAKE3 reference implementation family.
-- BLAKE3 is kept standalone because its tree hashing and XOF behavior differ a lot from the SHA modules.

local byte = string.byte
local floor = math.floor
local concat = table.concat

local IV = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

local CHUNK_START = 0x01
local CHUNK_END = 0x02
local PARENT = 0x04
local ROOT = 0x08
local KEYED_HASH = 0x10
local DERIVE_KEY_CONTEXT = 0x20
local DERIVE_KEY_MATERIAL = 0x40

local MESSAGE_PERMUTATION = {
	3, 7, 4, 11, 8, 1, 5, 14,
	2, 12, 13, 6, 10, 15, 16, 9,
}

local HEX = table.create(256)
for i = 0, 255 do
	HEX[i] = string.format("%02x", i)
end

local function u32(value)
	return bit32.band(value, 0xFFFFFFFF)
end

local function copy_words(words, count)
	count = count or #words
	local out = table.create(count)
	for i = 1, count do
		out[i] = words[i]
	end
	return out
end

local function fill_block_words_from_string(message, start_index, block_len, block_words)
	local byte_index = start_index
	for i = 1, 16 do
		local b1, b2, b3, b4 = byte(message, byte_index, byte_index + 3)
		block_words[i] = u32(
			(b1 or 0)
			+ bit32.lshift(b2 or 0, 8)
			+ bit32.lshift(b3 or 0, 16)
			+ bit32.lshift(b4 or 0, 24)
		)
		byte_index += 4
	end
end

local function write_word_le(out_bytes, index, word)
	out_bytes[index] = bit32.band(word, 0xFF)
	out_bytes[index + 1] = bit32.band(bit32.rshift(word, 8), 0xFF)
	out_bytes[index + 2] = bit32.band(bit32.rshift(word, 16), 0xFF)
	out_bytes[index + 3] = bit32.band(bit32.rshift(word, 24), 0xFF)
	return index + 4
end

local function bytes_to_hex(bytes)
	local parts = table.create(#bytes)
	for i = 1, #bytes do
		parts[i] = HEX[bytes[i]]
	end
	return concat(parts)
end

local function rotr32(value, shift)
	return bit32.rrotate(value, shift)
end

local function g(v, a, b, c, d, mx, my)
	v[a] = u32(v[a] + v[b] + mx)
	v[d] = rotr32(bit32.bxor(v[d], v[a]), 16)
	v[c] = u32(v[c] + v[d])
	v[b] = rotr32(bit32.bxor(v[b], v[c]), 12)
	v[a] = u32(v[a] + v[b] + my)
	v[d] = rotr32(bit32.bxor(v[d], v[a]), 8)
	v[c] = u32(v[c] + v[d])
	v[b] = rotr32(bit32.bxor(v[b], v[c]), 7)
end

local function permute_into(permuted, words)
	for i = 1, 16 do
		permuted[i] = words[MESSAGE_PERMUTATION[i]]
	end
end

local function compress_state(cv_words, block_words, block_len, counter, flags)
	local v = table.create(16)
	for i = 1, 8 do
		v[i] = cv_words[i]
		v[8 + i] = IV[i]
	end

	local counter_low = bit32.band(counter, 0xFFFFFFFF)
	local counter_high = bit32.band(math.floor(counter / 0x100000000), 0xFFFFFFFF)

	v[13] = counter_low
	v[14] = counter_high
	v[15] = block_len
	v[16] = flags

	local m = table.create(16)
	local next_m = table.create(16)
	for i = 1, 16 do
		m[i] = block_words[i]
	end

	for round_index = 1, 7 do
		g(v, 1, 5, 9, 13, m[1], m[2])
		g(v, 2, 6, 10, 14, m[3], m[4])
		g(v, 3, 7, 11, 15, m[5], m[6])
		g(v, 4, 8, 12, 16, m[7], m[8])
		g(v, 1, 6, 11, 16, m[9], m[10])
		g(v, 2, 7, 12, 13, m[11], m[12])
		g(v, 3, 8, 9, 14, m[13], m[14])
		g(v, 4, 5, 10, 15, m[15], m[16])

		if round_index < 7 then
			permute_into(next_m, m)
			m, next_m = next_m, m
		end
	end

	return v
end

local function compress_cv(cv_words, block_words, block_len, counter, flags)
	local state = compress_state(cv_words, block_words, block_len, counter, flags)
	local out = table.create(8)
	for i = 1, 8 do
		out[i] = bit32.bxor(state[i], state[8 + i])
	end
	return out
end

local function compress_xof_bytes(cv_words, block_words, block_len, counter, flags)
	local state = compress_state(cv_words, block_words, block_len, counter, flags)
	for i = 1, 8 do
		state[i] = bit32.bxor(state[i], state[8 + i])
		state[8 + i] = bit32.bxor(state[8 + i], cv_words[i])
	end
	local out = table.create(64)
	local index = 1
	for i = 1, 16 do
		index = write_word_le(out, index, state[i])
	end
	return out
end

local function chunk_start_flag(has_previous_block)
	if has_previous_block then
		return 0
	end
	return CHUNK_START
end

local function chunk_output_node(message, start_index, input_len, chunk_counter, key_words, flags)
	local cv = copy_words(key_words, 8)
	local remaining = input_len
	local position = start_index
	local has_previous_block = false
	local block_words = table.create(16)

	while remaining > 64 do
		fill_block_words_from_string(message, position, 64, block_words)
		cv = compress_cv(cv, block_words, 64, chunk_counter, bit32.bor(flags, chunk_start_flag(has_previous_block)))
		position += 64
		remaining -= 64
		has_previous_block = true
	end

	local final_block_words = table.create(16)
	fill_block_words_from_string(message, position, remaining, final_block_words)
	local final_flags = bit32.bor(flags, CHUNK_END, chunk_start_flag(has_previous_block))

	return {
		input_cv = cv,
		block_words = final_block_words,
		block_len = remaining,
		counter = chunk_counter,
		flags = final_flags,
	}
end

local function node_chaining_value(node)
	return compress_cv(node.input_cv, node.block_words, node.block_len, node.counter, node.flags)
end

local function node_root_bytes(node, out_len)
	local out = table.create(out_len)
	local produced = 0
	local seek = 0
	local root_flags = bit32.bor(node.flags, ROOT)

	while produced < out_len do
		local block_counter = floor(seek / 64)
		local offset = seek % 64
		local block = compress_xof_bytes(node.input_cv, node.block_words, node.block_len, block_counter, root_flags)
		local take = math.min(64 - offset, out_len - produced)
		for i = 1, take do
			out[produced + i] = block[offset + i]
		end
		produced += take
		seek += take
	end

	return out
end

local function round_down_to_power_of_two(value)
	local power = 1
	while (power * 2) <= value do
		power *= 2
	end
	return power
end

local function left_subtree_len(input_len)
	local full_chunks = floor((input_len - 1) / 1024)
	return round_down_to_power_of_two(full_chunks) * 1024
end

local function hash_subtree(message, start_index, input_len, chunk_counter, key_words, flags)
	if input_len <= 1024 then
		return chunk_output_node(message, start_index, input_len, chunk_counter, key_words, flags)
	end

	local left_len = left_subtree_len(input_len)
	local right_len = input_len - left_len
	local left_node = hash_subtree(message, start_index, left_len, chunk_counter, key_words, flags)
	local right_node = hash_subtree(message, start_index + left_len, right_len, chunk_counter + (left_len / 1024), key_words, flags)

	local left_cv = node_chaining_value(left_node)
	local right_cv = node_chaining_value(right_node)
	local block_words = table.create(16)
	for i = 1, 8 do
		block_words[i] = left_cv[i]
	end
	for i = 1, 8 do
		block_words[8 + i] = right_cv[i]
	end

	return {
		input_cv = copy_words(key_words, 8),
		block_words = block_words,
		block_len = 64,
		counter = 0,
		flags = bit32.bor(flags, PARENT),
	}
end

local function blake3_hex(message, out_len)
	if type(message) ~= "string" then
		error("BLAKE3 input must be a string", 2)
	end

	out_len = out_len or 32
	if out_len < 1 then
		error("BLAKE3 output length must be at least 1 byte", 2)
	end

	local root_node = hash_subtree(message, 1, #message, 0, IV, 0)
	local out_bytes = node_root_bytes(root_node, out_len)
	return bytes_to_hex(out_bytes)
end

local algorithms = {
	blake3 = blake3_hex,
}

return {
	hash = blake3_hex,
	blake3 = blake3_hex,
	blake3_hex = blake3_hex,
	algorithms = algorithms,
}
