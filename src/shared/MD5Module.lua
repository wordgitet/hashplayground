--!strict
--!native
-- SPDX-License-Identifier: Unlicense OR MPL-2.0
-- Hash Playground Rojo export.
-- Ported from Zunawe/md5-c (Unlicense).
-- MD5 is kept in its own module so the GUI can swap algorithms without special cases.

local S = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21}

local K = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391}

local PADDING = {0x80}
for i = 2, 64 do
	PADDING[i] = 0x00
end

local HEX = table.create(256)
for i = 0, 255 do
	HEX[i] = string.format("%02x", i)
end

local function F(x, y, z)
	return bit32.bor(bit32.band(x, y), bit32.band(bit32.bnot(x), z))
end

local function G(x, y, z)
	return bit32.bor(bit32.band(x, z), bit32.band(y, bit32.bnot(z)))
end

local function H(x, y, z)
	return bit32.bxor(x, y, z)
end

local function I(x, y, z)
	return bit32.bxor(y, bit32.bor(x, bit32.bnot(z)))
end

local function add32(a, b)
	return bit32.band(a + b, 0xFFFFFFFF)
end

local function md5_step(buffer, input)
	local AA = buffer[1]
	local BB = buffer[2]
	local CC = buffer[3]
	local DD = buffer[4]

	for i = 1, 64 do
		local E, j
		local r = math.floor((i - 1) / 16)
		if r == 0 then
			E = F(BB, CC, DD)
			j = i
		elseif r == 1 then
			E = G(BB, CC, DD)
			j = (((i - 1) * 5) + 1) % 16 + 1
		elseif r == 2 then
			E = H(BB, CC, DD)
			j = (((i - 1) * 3) + 5) % 16 + 1
		else
			E = I(BB, CC, DD)
			j = ((i - 1) * 7) % 16 + 1
		end

		local temp = DD
		DD = CC
		CC = BB
		BB = add32(BB, bit32.lrotate(add32(add32(AA, E), add32(K[i], input[j])), S[i]))
		AA = temp
	end

	buffer[1] = add32(buffer[1], AA)
	buffer[2] = add32(buffer[2], BB)
	buffer[3] = add32(buffer[3], CC)
	buffer[4] = add32(buffer[4], DD)
end

local function fill_block_from_string(block, text, start_index, byte_count)
	local byte_index = start_index
	for word_index = 1, 16 do
		local b1, b2, b3, b4 = string.byte(text, byte_index, byte_index + 3)
		block[word_index] = bit32.bor(
			b1 or 0,
			bit32.lshift(b2 or 0, 8),
			bit32.lshift(b3 or 0, 16),
			bit32.lshift(b4 or 0, 24)
		)
		byte_index += 4
	end
end

local function append_word_hex_le(parts, index, word)
	parts[index] = HEX[bit32.band(word, 0xFF)]
	parts[index + 1] = HEX[bit32.band(bit32.rshift(word, 8), 0xFF)]
	parts[index + 2] = HEX[bit32.band(bit32.rshift(word, 16), 0xFF)]
	parts[index + 3] = HEX[bit32.band(bit32.rshift(word, 24), 0xFF)]
	return index + 4
end

local function md5_string(s)
	local message_len = #s
	local buffer = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	local block = table.create(16)
	local full_chunks = message_len - (message_len % 64)

	for chunk_start = 1, full_chunks, 64 do
		fill_block_from_string(block, s, chunk_start, 64)
		md5_step(buffer, block)
	end

	local tail_len = message_len - full_chunks
	local tail = table.create(128, 0)
	for i = 1, tail_len do
		tail[i] = string.byte(s, full_chunks + i)
	end
	tail[tail_len + 1] = 0x80

	local tail_total_len = tail_len < 56 and 64 or 128
	local bit_length_lo = bit32.band(message_len * 8, 0xFFFFFFFF)
	local bit_length_hi = bit32.band(math.floor(message_len * 8 / 0x100000000), 0xFFFFFFFF)

	tail[tail_total_len - 7] = bit32.band(bit_length_lo, 0xFF)
	tail[tail_total_len - 6] = bit32.band(bit32.rshift(bit_length_lo, 8), 0xFF)
	tail[tail_total_len - 5] = bit32.band(bit32.rshift(bit_length_lo, 16), 0xFF)
	tail[tail_total_len - 4] = bit32.band(bit32.rshift(bit_length_lo, 24), 0xFF)
	tail[tail_total_len - 3] = bit32.band(bit_length_hi, 0xFF)
	tail[tail_total_len - 2] = bit32.band(bit32.rshift(bit_length_hi, 8), 0xFF)
	tail[tail_total_len - 1] = bit32.band(bit32.rshift(bit_length_hi, 16), 0xFF)
	tail[tail_total_len] = bit32.band(bit32.rshift(bit_length_hi, 24), 0xFF)

	for block_start = 1, tail_total_len, 64 do
		local tail_index = block_start
		for word_index = 1, 16 do
			block[word_index] = bit32.bor(
				tail[tail_index] or 0,
				bit32.lshift(tail[tail_index + 1] or 0, 8),
				bit32.lshift(tail[tail_index + 2] or 0, 16),
				bit32.lshift(tail[tail_index + 3] or 0, 24)
			)
			tail_index += 4
		end
		md5_step(buffer, block)
	end

	local parts = table.create(16)
	local hex_index = 1
	for i = 1, 4 do
		hex_index = append_word_hex_le(parts, hex_index, buffer[i])
	end
	return table.concat(parts)
end

local algorithms = {
	md5 = md5_string,
}

return {
	hash = md5_string,
	md5 = md5_string,
	algorithms = algorithms,
}
