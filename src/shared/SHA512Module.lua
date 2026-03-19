--!strict
--!native
-- SPDX-License-Identifier: Apache-2.0
-- Hash Playground Rojo export.
-- Ported from the OpenSSL SHA-512 implementation.
-- SHA-512 uses split 32-bit halves so it stays portable in Luau without native 64-bit integers.

local band = bit32.band
local bor = bit32.bor
local bxor = bit32.bxor
local bnot = bit32.bnot
local rshift = bit32.rshift
local lshift = bit32.lshift
local byte = string.byte
local char = string.char
local rep = string.rep
local format = string.format
local floor = math.floor

local MASK32 = 0xFFFFFFFF
local UINT32 = 0x100000000
local BLOCK_SIZE = 128

local K_HI = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f,
	0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
	0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4,
	0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
}

local K_LO = {
	0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc,
	0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
	0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2,
	0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
	0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
	0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
	0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4,
	0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
	0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df,
	0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
	0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30,
	0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
	0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8,
	0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
	0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
	0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
	0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178,
	0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
	0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c,
	0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
}

local H0_HI = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local H0_LO = {
	0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
	0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
}

local W_HI = table.create(80)
local W_LO = table.create(80)

local function u32(value)
	return band(value, MASK32)
end

local function add2(ahi, alo, bhi, blo)
	local lo = alo + blo
	local hi = ahi + bhi
	if lo >= UINT32 then
		hi += floor(lo / UINT32)
		lo = lo % UINT32
	end
	return u32(hi), u32(lo)
end

local function add4(ahi, alo, bhi, blo, chi, clo, dhi, dlo)
	local lo = alo + blo + clo + dlo
	local hi = ahi + bhi + chi + dhi
	if lo >= UINT32 then
		hi += floor(lo / UINT32)
		lo = lo % UINT32
	end
	return u32(hi), u32(lo)
end

local function add5(ahi, alo, bhi, blo, chi, clo, dhi, dlo, ehi, elo)
	local lo = alo + blo + clo + dlo + elo
	local hi = ahi + bhi + chi + dhi + ehi
	if lo >= UINT32 then
		hi += floor(lo / UINT32)
		lo = lo % UINT32
	end
	return u32(hi), u32(lo)
end

local function rotr(hi, lo, shift)
	if shift == 0 then
		return hi, lo
	elseif shift < 32 then
		return u32(bor(rshift(hi, shift), lshift(lo, 32 - shift))), u32(bor(rshift(lo, shift), lshift(hi, 32 - shift)))
	elseif shift == 32 then
		return lo, hi
	else
		local s = shift - 32
		return u32(bor(rshift(lo, s), lshift(hi, 32 - s))), u32(bor(rshift(hi, s), lshift(lo, 32 - s)))
	end
end

local function shr(hi, lo, shift)
	if shift == 0 then
		return hi, lo
	elseif shift < 32 then
		return rshift(hi, shift), u32(bor(rshift(lo, shift), lshift(hi, 32 - shift)))
	elseif shift == 32 then
		return 0, hi
	else
		return 0, rshift(hi, shift - 32)
	end
end

local function big0(hi, lo)
	local a_hi, a_lo = rotr(hi, lo, 28)
	local b_hi, b_lo = rotr(hi, lo, 34)
	local c_hi, c_lo = rotr(hi, lo, 39)
	return bxor(a_hi, b_hi, c_hi), bxor(a_lo, b_lo, c_lo)
end

local function big1(hi, lo)
	local a_hi, a_lo = rotr(hi, lo, 14)
	local b_hi, b_lo = rotr(hi, lo, 18)
	local c_hi, c_lo = rotr(hi, lo, 41)
	return bxor(a_hi, b_hi, c_hi), bxor(a_lo, b_lo, c_lo)
end

local function small0(hi, lo)
	local a_hi, a_lo = rotr(hi, lo, 1)
	local b_hi, b_lo = rotr(hi, lo, 8)
	local c_hi, c_lo = shr(hi, lo, 7)
	return bxor(a_hi, b_hi, c_hi), bxor(a_lo, b_lo, c_lo)
end

local function small1(hi, lo)
	local a_hi, a_lo = rotr(hi, lo, 19)
	local b_hi, b_lo = rotr(hi, lo, 61)
	local c_hi, c_lo = shr(hi, lo, 6)
	return bxor(a_hi, b_hi, c_hi), bxor(a_lo, b_lo, c_lo)
end

local function ch(eh, el, fh, fl, gh, gl)
	return bxor(band(eh, fh), band(bnot(eh), gh)), bxor(band(el, fl), band(bnot(el), gl))
end

local function maj(ah, al, bh, bl, chh, chl)
	return bxor(band(ah, bh), band(ah, chh), band(bh, chh)), bxor(band(al, bl), band(al, chl), band(bl, chl))
end

local function read64_be(text, index)
	local b1, b2, b3, b4, b5, b6, b7, b8 = byte(text, index, index + 7)
	return u32(bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)), u32(bor(lshift(b5, 24), lshift(b6, 16), lshift(b7, 8), b8))
end

local function pack64_be(hi, lo)
	return char(
		band(rshift(hi, 24), 0xFF), band(rshift(hi, 16), 0xFF), band(rshift(hi, 8), 0xFF), band(hi, 0xFF),
		band(rshift(lo, 24), 0xFF), band(rshift(lo, 16), 0xFF), band(rshift(lo, 8), 0xFF), band(lo, 0xFF)
	)
end

local function append64_hex(parts, index, hi, lo)
	parts[index] = format("%02x", band(rshift(hi, 24), 0xFF))
	parts[index + 1] = format("%02x", band(rshift(hi, 16), 0xFF))
	parts[index + 2] = format("%02x", band(rshift(hi, 8), 0xFF))
	parts[index + 3] = format("%02x", band(hi, 0xFF))
	parts[index + 4] = format("%02x", band(rshift(lo, 24), 0xFF))
	parts[index + 5] = format("%02x", band(rshift(lo, 16), 0xFF))
	parts[index + 6] = format("%02x", band(rshift(lo, 8), 0xFF))
	parts[index + 7] = format("%02x", band(lo, 0xFF))
	return index + 8
end

local function sha512_state(message)
	if type(message) ~= "string" then
		error("SHA-512 input must be a string", 2)
	end

	local message_len = #message
	local pad_zeros = (112 - ((message_len + 1) % BLOCK_SIZE)) % BLOCK_SIZE
	local bit_len_lo = band(message_len * 8, MASK32)
	local bit_len_hi = band(floor(message_len / 0x20000000), MASK32)
	local padded = message .. char(0x80) .. rep(char(0), pad_zeros) .. pack64_be(0, 0) .. pack64_be(bit_len_hi, bit_len_lo)

	local h_hi = table.create(8)
	local h_lo = table.create(8)
	for i = 1, 8 do
		h_hi[i] = H0_HI[i]
		h_lo[i] = H0_LO[i]
	end

	for block_start = 1, #padded, BLOCK_SIZE do
		for i = 1, 16 do
			W_HI[i], W_LO[i] = read64_be(padded, block_start + ((i - 1) * 8))
		end

		for i = 17, 80 do
			local s0_hi, s0_lo = small0(W_HI[i - 15], W_LO[i - 15])
			local s1_hi, s1_lo = small1(W_HI[i - 2], W_LO[i - 2])
			W_HI[i], W_LO[i] = add4(W_HI[i - 16], W_LO[i - 16], s0_hi, s0_lo, W_HI[i - 7], W_LO[i - 7], s1_hi, s1_lo)
		end

		local a_hi, a_lo = h_hi[1], h_lo[1]
		local b_hi, b_lo = h_hi[2], h_lo[2]
		local c_hi, c_lo = h_hi[3], h_lo[3]
		local d_hi, d_lo = h_hi[4], h_lo[4]
		local e_hi, e_lo = h_hi[5], h_lo[5]
		local f_hi, f_lo = h_hi[6], h_lo[6]
		local g_hi, g_lo = h_hi[7], h_lo[7]
		local hh_hi, hh_lo = h_hi[8], h_lo[8]

		for i = 1, 80 do
			local s1_hi, s1_lo = big1(e_hi, e_lo)
			local ch_hi, ch_lo = ch(e_hi, e_lo, f_hi, f_lo, g_hi, g_lo)
			local t1_hi, t1_lo = add5(hh_hi, hh_lo, s1_hi, s1_lo, ch_hi, ch_lo, K_HI[i], K_LO[i], W_HI[i], W_LO[i])
			local s0_hi, s0_lo = big0(a_hi, a_lo)
			local maj_hi, maj_lo = maj(a_hi, a_lo, b_hi, b_lo, c_hi, c_lo)
			local t2_hi, t2_lo = add2(s0_hi, s0_lo, maj_hi, maj_lo)

			hh_hi, hh_lo = g_hi, g_lo
			g_hi, g_lo = f_hi, f_lo
			f_hi, f_lo = e_hi, e_lo
			e_hi, e_lo = add2(d_hi, d_lo, t1_hi, t1_lo)
			d_hi, d_lo = c_hi, c_lo
			c_hi, c_lo = b_hi, b_lo
			b_hi, b_lo = a_hi, a_lo
			a_hi, a_lo = add2(t1_hi, t1_lo, t2_hi, t2_lo)
		end

		h_hi[1], h_lo[1] = add2(h_hi[1], h_lo[1], a_hi, a_lo)
		h_hi[2], h_lo[2] = add2(h_hi[2], h_lo[2], b_hi, b_lo)
		h_hi[3], h_lo[3] = add2(h_hi[3], h_lo[3], c_hi, c_lo)
		h_hi[4], h_lo[4] = add2(h_hi[4], h_lo[4], d_hi, d_lo)
		h_hi[5], h_lo[5] = add2(h_hi[5], h_lo[5], e_hi, e_lo)
		h_hi[6], h_lo[6] = add2(h_hi[6], h_lo[6], f_hi, f_lo)
		h_hi[7], h_lo[7] = add2(h_hi[7], h_lo[7], g_hi, g_lo)
		h_hi[8], h_lo[8] = add2(h_hi[8], h_lo[8], hh_hi, hh_lo)
	end

	return h_hi, h_lo
end

local function sha512_bytes(message)
	local h_hi, h_lo = sha512_state(message)
	local parts = table.create(8)
	for i = 1, 8 do
		parts[i] = pack64_be(h_hi[i], h_lo[i])
	end
	return table.concat(parts)
end

local function sha512_hex(message)
	local h_hi, h_lo = sha512_state(message)
	local hex_parts = table.create(64)
	local hex_index = 1
	for i = 1, 8 do
		hex_index = append64_hex(hex_parts, hex_index, h_hi[i], h_lo[i])
	end

	return table.concat(hex_parts)
end

local algorithms = {
	sha512 = sha512_hex,
}

return {
	hash = sha512_hex,
	sha512 = sha512_hex,
	sha512_512 = sha512_hex,
	sha512_bytes = sha512_bytes,
	digest_bytes = sha512_bytes,
	block_size = 128,
	digest_size = 64,
	algorithms = algorithms,
}
