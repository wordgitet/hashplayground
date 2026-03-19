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

local function md5_init()
	return {
		size = 0,
		buffer = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476},
		input = {},
		digest = {},
	}
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

local function md5_update(ctx, input_buffer, input_len)
	local offset = ctx.size % 64
	ctx.size = ctx.size + input_len

	for i = 1, input_len do
		ctx.input[offset + 1] = input_buffer[i]
		offset = offset + 1

		if offset % 64 == 0 then
			local block = {}
			for j = 0, 15 do
				block[j + 1] = bit32.bor(
					bit32.lshift(ctx.input[j * 4 + 4], 24),
					bit32.lshift(ctx.input[j * 4 + 3], 16),
					bit32.lshift(ctx.input[j * 4 + 2], 8),
					ctx.input[j * 4 + 1]
				)
			end
			md5_step(ctx.buffer, block)
			offset = 0
		end
	end
end

local function md5_finalize(ctx)
	local offset = ctx.size % 64
	local padding_length = offset < 56 and (56 - offset) or (120 - offset)

	md5_update(ctx, PADDING, padding_length)
	ctx.size = ctx.size - padding_length

	local block = {}
	for j = 0, 13 do
		block[j + 1] = bit32.bor(
			bit32.lshift(ctx.input[j * 4 + 4], 24),
			bit32.lshift(ctx.input[j * 4 + 3], 16),
			bit32.lshift(ctx.input[j * 4 + 2], 8),
			ctx.input[j * 4 + 1]
		)
	end
	block[15] = bit32.band(ctx.size * 8, 0xFFFFFFFF)
	block[16] = bit32.band(math.floor(ctx.size * 8 / 0x100000000), 0xFFFFFFFF)

	md5_step(ctx.buffer, block)

	for i = 0, 3 do
		ctx.digest[i * 4 + 1] = bit32.band(ctx.buffer[i + 1], 0xFF)
		ctx.digest[i * 4 + 2] = bit32.band(bit32.rshift(ctx.buffer[i + 1], 8), 0xFF)
		ctx.digest[i * 4 + 3] = bit32.band(bit32.rshift(ctx.buffer[i + 1], 16), 0xFF)
		ctx.digest[i * 4 + 4] = bit32.band(bit32.rshift(ctx.buffer[i + 1], 24), 0xFF)
	end
end

local function md5_string(s)
	local ctx = md5_init()
	local bytes = {}
	for i = 1, #s do
		bytes[i] = string.byte(s, i)
	end
	md5_update(ctx, bytes, #s)
	md5_finalize(ctx)
	local hex = ""
	for i = 1, 16 do
		hex = hex .. string.format("%02x", ctx.digest[i])
	end
	return hex
end

local algorithms = {
	md5 = md5_string,
}

return {
	hash = md5_string,
	md5 = md5_string,
	algorithms = algorithms,
}
