--!strict
--!native
-- SPDX-License-Identifier: LicenseRef-B-Con-Public-Domain
-- Hash Playground Rojo export.
-- Ported from the Brad Conte crypto-algorithms implementation (public domain).
-- SHA-256 exposes both hex and raw digest bytes so HMAC/PBKDF2 can reuse the same core.

local K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local H0 = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local function u32(value)
	return bit32.band(value, 0xFFFFFFFF)
end

local function rotr(value, shift)
	return bit32.rrotate(value, shift)
end

local function shr(value, shift)
	return bit32.rshift(value, shift)
end

local function ch(x, y, z)
	return bit32.bxor(bit32.band(x, y), bit32.band(bit32.bnot(x), z))
end

local function maj(x, y, z)
	return bit32.bxor(bit32.band(x, y), bit32.band(x, z), bit32.band(y, z))
end

local function small_sigma0(x)
	return bit32.bxor(rotr(x, 7), rotr(x, 18), shr(x, 3))
end

local function small_sigma1(x)
	return bit32.bxor(rotr(x, 17), rotr(x, 19), shr(x, 10))
end

local function big_sigma0(x)
	return bit32.bxor(rotr(x, 2), rotr(x, 13), rotr(x, 22))
end

local function big_sigma1(x)
	return bit32.bxor(rotr(x, 6), rotr(x, 11), rotr(x, 25))
end

local function process_message(message)
	local bytes = {}
	for i = 1, #message do
		bytes[i] = string.byte(message, i)
	end

	local bit_length = #bytes * 8
	bytes[#bytes + 1] = 0x80

	while (#bytes % 64) ~= 56 do
		bytes[#bytes + 1] = 0x00
	end

	local high = math.floor(bit_length / 0x100000000)
	local low = bit_length % 0x100000000

	bytes[#bytes + 1] = bit32.band(bit32.rshift(high, 24), 0xFF)
	bytes[#bytes + 1] = bit32.band(bit32.rshift(high, 16), 0xFF)
	bytes[#bytes + 1] = bit32.band(bit32.rshift(high, 8), 0xFF)
	bytes[#bytes + 1] = bit32.band(high, 0xFF)
	bytes[#bytes + 1] = bit32.band(bit32.rshift(low, 24), 0xFF)
	bytes[#bytes + 1] = bit32.band(bit32.rshift(low, 16), 0xFF)
	bytes[#bytes + 1] = bit32.band(bit32.rshift(low, 8), 0xFF)
	bytes[#bytes + 1] = bit32.band(low, 0xFF)

	local h = {
		H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8],
	}

	for chunk_start = 1, #bytes, 64 do
		local w = table.create(64)

		for i = 1, 16 do
			local j = chunk_start + ((i - 1) * 4)
			w[i] = u32(
				bit32.lshift(bytes[j], 24)
				+ bit32.lshift(bytes[j + 1], 16)
				+ bit32.lshift(bytes[j + 2], 8)
				+ bytes[j + 3]
			)
		end

		for i = 17, 64 do
			w[i] = u32(w[i - 16] + small_sigma0(w[i - 15]) + w[i - 7] + small_sigma1(w[i - 2]))
		end

		local a = h[1]
		local b = h[2]
		local c = h[3]
		local d = h[4]
		local e = h[5]
		local f = h[6]
		local g = h[7]
		local hh = h[8]

		for i = 1, 64 do
			local temp1 = u32(hh + big_sigma1(e) + ch(e, f, g) + K[i] + w[i])
			local temp2 = u32(big_sigma0(a) + maj(a, b, c))
			hh = g
			g = f
			f = e
			e = u32(d + temp1)
			d = c
			c = b
			b = a
			a = u32(temp1 + temp2)
		end

		h[1] = u32(h[1] + a)
		h[2] = u32(h[2] + b)
		h[3] = u32(h[3] + c)
		h[4] = u32(h[4] + d)
		h[5] = u32(h[5] + e)
		h[6] = u32(h[6] + f)
		h[7] = u32(h[7] + g)
		h[8] = u32(h[8] + hh)
	end

	return h
end

local function sha256_bytes(message)
	local digest = process_message(message)
	local parts = table.create(8)
	for i = 1, 8 do
		local word = digest[i]
		parts[i] = string.char(
			bit32.band(bit32.rshift(word, 24), 0xFF),
			bit32.band(bit32.rshift(word, 16), 0xFF),
			bit32.band(bit32.rshift(word, 8), 0xFF),
			bit32.band(word, 0xFF)
		)
	end
	return table.concat(parts)
end

local function sha256_hex(message)
	local digest = process_message(message)
	local hex = ""
	for i = 1, 8 do
		hex = hex .. string.format("%08x", digest[i])
	end
	return hex
end

local algorithms = {
	sha256 = sha256_hex,
}

return {
	hash = sha256_hex,
	sha256 = sha256_hex,
	sha256_hex = sha256_hex,
	sha256_bytes = sha256_bytes,
	digest_bytes = sha256_bytes,
	block_size = 64,
	digest_size = 32,
	algorithms = algorithms,
}
