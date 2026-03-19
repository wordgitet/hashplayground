--!strict
--!native
-- SPDX-License-Identifier: Apache-2.0
-- Hash Playground Rojo export.
-- Ported from the BLAKE2 reference implementation family.
-- BLAKE2b remains hex-focused in the UI, but the core stays isolated for future keyed or variable-length modes.

local IV_LO = {
	0xF3BCC908, 0x84CAA73B, 0xFE94F82B, 0x5F1D36F1,
	0xADE682D1, 0x2B3E6C1F, 0xFB41BD6B, 0x137E2179,
}

local IV_HI = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

local SIGMA = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

local function u32(value)
	return bit32.band(value, 0xFFFFFFFF)
end

local function add64(a_lo, a_hi, b_lo, b_hi)
	local lo = a_lo + b_lo
	local carry = 0
	if lo >= 0x100000000 then
		lo -= 0x100000000
		carry = 1
	end

	local hi = a_hi + b_hi + carry
	if hi >= 0x100000000 then
		hi -= 0x100000000
	end

	return u32(lo), u32(hi)
end

local function xor64(a_lo, a_hi, b_lo, b_hi)
	return bit32.bxor(a_lo, b_lo), bit32.bxor(a_hi, b_hi)
end

local function rotr64(lo, hi, shift)
	shift %= 64
	if shift == 0 then
		return lo, hi
	elseif shift < 32 then
		local new_lo = bit32.bor(bit32.rshift(lo, shift), bit32.lshift(hi, 32 - shift))
		local new_hi = bit32.bor(bit32.rshift(hi, shift), bit32.lshift(lo, 32 - shift))
		return u32(new_lo), u32(new_hi)
	elseif shift == 32 then
		return hi, lo
	else
		local s = shift - 32
		local new_lo = bit32.bor(bit32.rshift(hi, s), bit32.lshift(lo, 32 - s))
		local new_hi = bit32.bor(bit32.rshift(lo, s), bit32.lshift(hi, 32 - s))
		return u32(new_lo), u32(new_hi)
	end
end

local function load_message_bytes(message)
	local bytes = table.create(#message)
	for i = 1, #message do
		bytes[i] = string.byte(message, i)
	end
	return bytes
end

local function load_word_le(bytes, start_index)
	local b1 = bytes[start_index] or 0
	local b2 = bytes[start_index + 1] or 0
	local b3 = bytes[start_index + 2] or 0
	local b4 = bytes[start_index + 3] or 0
	local b5 = bytes[start_index + 4] or 0
	local b6 = bytes[start_index + 5] or 0
	local b7 = bytes[start_index + 6] or 0
	local b8 = bytes[start_index + 7] or 0

	local lo = bit32.bor(
		b1,
		bit32.lshift(b2, 8),
		bit32.lshift(b3, 16),
		bit32.lshift(b4, 24)
	)
	local hi = bit32.bor(
		b5,
		bit32.lshift(b6, 8),
		bit32.lshift(b7, 16),
		bit32.lshift(b8, 24)
	)

	return u32(lo), u32(hi)
end

local function g(v_lo, v_hi, a, b, c, d, x_lo, x_hi, y_lo, y_hi)
	v_lo[a], v_hi[a] = add64(v_lo[a], v_hi[a], v_lo[b], v_hi[b])
	v_lo[a], v_hi[a] = add64(v_lo[a], v_hi[a], x_lo, x_hi)

	v_lo[d], v_hi[d] = xor64(v_lo[d], v_hi[d], v_lo[a], v_hi[a])
	v_lo[d], v_hi[d] = rotr64(v_lo[d], v_hi[d], 32)

	v_lo[c], v_hi[c] = add64(v_lo[c], v_hi[c], v_lo[d], v_hi[d])

	v_lo[b], v_hi[b] = xor64(v_lo[b], v_hi[b], v_lo[c], v_hi[c])
	v_lo[b], v_hi[b] = rotr64(v_lo[b], v_hi[b], 24)

	v_lo[a], v_hi[a] = add64(v_lo[a], v_hi[a], v_lo[b], v_hi[b])
	v_lo[a], v_hi[a] = add64(v_lo[a], v_hi[a], y_lo, y_hi)

	v_lo[d], v_hi[d] = xor64(v_lo[d], v_hi[d], v_lo[a], v_hi[a])
	v_lo[d], v_hi[d] = rotr64(v_lo[d], v_hi[d], 16)

	v_lo[c], v_hi[c] = add64(v_lo[c], v_hi[c], v_lo[d], v_hi[d])

	v_lo[b], v_hi[b] = xor64(v_lo[b], v_hi[b], v_lo[c], v_hi[c])
	v_lo[b], v_hi[b] = rotr64(v_lo[b], v_hi[b], 63)
end

local function compress(h_lo, h_hi, bytes, block_start, counter_lo, counter_hi, is_last)
	local v_lo = table.create(16)
	local v_hi = table.create(16)
	local m_lo = table.create(16)
	local m_hi = table.create(16)

	for i = 1, 8 do
		v_lo[i] = h_lo[i]
		v_hi[i] = h_hi[i]
		v_lo[8 + i] = IV_LO[i]
		v_hi[8 + i] = IV_HI[i]
	end

	v_lo[13], v_hi[13] = xor64(v_lo[13], v_hi[13], counter_lo, counter_hi)
	if is_last then
		v_lo[15], v_hi[15] = xor64(v_lo[15], v_hi[15], 0xFFFFFFFF, 0xFFFFFFFF)
	end

	local word_start = block_start
	for i = 1, 16 do
		m_lo[i], m_hi[i] = load_word_le(bytes, word_start)
		word_start += 8
	end

	for round_index = 1, 12 do
		local s = SIGMA[round_index]

		g(v_lo, v_hi, 1, 5, 9, 13, m_lo[s[1] + 1], m_hi[s[1] + 1], m_lo[s[2] + 1], m_hi[s[2] + 1])
		g(v_lo, v_hi, 2, 6, 10, 14, m_lo[s[3] + 1], m_hi[s[3] + 1], m_lo[s[4] + 1], m_hi[s[4] + 1])
		g(v_lo, v_hi, 3, 7, 11, 15, m_lo[s[5] + 1], m_hi[s[5] + 1], m_lo[s[6] + 1], m_hi[s[6] + 1])
		g(v_lo, v_hi, 4, 8, 12, 16, m_lo[s[7] + 1], m_hi[s[7] + 1], m_lo[s[8] + 1], m_hi[s[8] + 1])
		g(v_lo, v_hi, 1, 6, 11, 16, m_lo[s[9] + 1], m_hi[s[9] + 1], m_lo[s[10] + 1], m_hi[s[10] + 1])
		g(v_lo, v_hi, 2, 7, 12, 13, m_lo[s[11] + 1], m_hi[s[11] + 1], m_lo[s[12] + 1], m_hi[s[12] + 1])
		g(v_lo, v_hi, 3, 8, 9, 14, m_lo[s[13] + 1], m_hi[s[13] + 1], m_lo[s[14] + 1], m_hi[s[14] + 1])
		g(v_lo, v_hi, 4, 5, 10, 15, m_lo[s[15] + 1], m_hi[s[15] + 1], m_lo[s[16] + 1], m_hi[s[16] + 1])
	end

	for i = 1, 8 do
		h_lo[i], h_hi[i] = xor64(h_lo[i], h_hi[i], v_lo[i], v_hi[i])
		h_lo[i], h_hi[i] = xor64(h_lo[i], h_hi[i], v_lo[8 + i], v_hi[8 + i])
	end
end

local function append_word_bytes(hex_parts, hex_index, lo, hi, outlen)
	for byte_index = 0, 3 do
		if hex_index > outlen then
			return hex_index
		end
		hex_parts[hex_index] = string.format("%02x", bit32.band(bit32.rshift(lo, byte_index * 8), 0xFF))
		hex_index += 1
	end

	for byte_index = 0, 3 do
		if hex_index > outlen then
			return hex_index
		end
		hex_parts[hex_index] = string.format("%02x", bit32.band(bit32.rshift(hi, byte_index * 8), 0xFF))
		hex_index += 1
	end

	return hex_index
end

local function blake2b_hex(message, outlen)
	if type(message) ~= "string" then
		error("BLAKE2b input must be a string", 2)
	end

	outlen = outlen or 64
	if outlen < 1 or outlen > 64 then
		error("BLAKE2b digest length must be between 1 and 64 bytes", 2)
	end

	local bytes = load_message_bytes(message)
	local h_lo = table.create(8)
	local h_hi = table.create(8)

	for i = 1, 8 do
		h_lo[i] = IV_LO[i]
		h_hi[i] = IV_HI[i]
	end

	local param_lo = bit32.bor(
		outlen,
		bit32.lshift(1, 16),
		bit32.lshift(1, 24)
	)
	h_lo[1] = bit32.bxor(h_lo[1], param_lo)

	local counter_lo = 0
	local counter_hi = 0
	local total_len = #bytes
	local offset = 1

	local non_final_blocks = 0
	if total_len > 0 then
		non_final_blocks = math.floor((total_len - 1) / 128)
	end

	for _ = 1, non_final_blocks do
		counter_lo, counter_hi = add64(counter_lo, counter_hi, 128, 0)
		compress(h_lo, h_hi, bytes, offset, counter_lo, counter_hi, false)
		offset += 128
	end

	local final_len = total_len - (non_final_blocks * 128)
	counter_lo, counter_hi = add64(counter_lo, counter_hi, final_len, 0)
	compress(h_lo, h_hi, bytes, offset, counter_lo, counter_hi, true)

	local hex_parts = table.create(outlen)
	local hex_index = 1
	for i = 1, 8 do
		hex_index = append_word_bytes(hex_parts, hex_index, h_lo[i], h_hi[i], outlen)
		if hex_index > outlen then
			break
		end
	end

	return table.concat(hex_parts)
end

local algorithms = {
	blake2b = blake2b_hex,
}

return {
	hash = blake2b_hex,
	blake2b = blake2b_hex,
	blake2b_512 = blake2b_hex,
	algorithms = algorithms,
}
