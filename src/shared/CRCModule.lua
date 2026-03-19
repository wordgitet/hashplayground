--!strict
--!native
-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- CRC presets are centralized here so the UI can expose named variants without duplicating math.

local CRC_PRESETS = {
	crc8 = {
		width = 8,
		poly = 0x07,
		init = 0x00,
		refin = false,
		refout = false,
		xorout = 0x00,
	},
	crc16 = {
		width = 16,
		poly = 0xA001,
		init = 0x0000,
		refin = true,
		refout = true,
		xorout = 0x0000,
	},
	crc24 = {
		width = 24,
		poly = 0x864CFB,
		init = 0xB704CE,
		refin = false,
		refout = false,
		xorout = 0x000000,
	},
	crc32 = {
		width = 32,
		poly = 0xEDB88320,
		init = 0xFFFFFFFF,
		refin = true,
		refout = true,
		xorout = 0xFFFFFFFF,
	},
}

local function mask_for_width(width)
	if width == 32 then
		return 0xFFFFFFFF
	end
	return bit32.band(bit32.lshift(1, width) - 1, 0xFFFFFFFF)
end

local function reflect_bits(value, width)
	local reflected = 0
	for bit_index = 0, width - 1 do
		if bit32.band(value, bit32.lshift(1, bit_index)) ~= 0 then
			reflected = bit32.bor(reflected, bit32.lshift(1, width - 1 - bit_index))
		end
	end
	return reflected
end

local function normalize_crc_preset(preset_or_name)
	if type(preset_or_name) == "string" then
		local preset = CRC_PRESETS[preset_or_name]
		if not preset then
			error("Unknown CRC preset: " .. preset_or_name, 2)
		end
		return preset
	end

	if preset_or_name == nil then
		return CRC_PRESETS.crc32
	end

	return preset_or_name
end

local function crc_compute(s, preset_or_name)
	local preset = normalize_crc_preset(preset_or_name)
	local width = preset.width

	if width < 8 or width > 32 then
		error("CRC width must be between 8 and 32 bits", 2)
	end

	local mask = mask_for_width(width)
	local crc = bit32.band(preset.init, mask)
	local refin = preset.refin == true
	local refout = preset.refout == true
	local poly = bit32.band(preset.poly, mask)

	for i = 1, #s do
		local byte = string.byte(s, i)
		if refin then
			crc = bit32.bxor(crc, byte)
			for _ = 1, 8 do
				if bit32.band(crc, 1) ~= 0 then
					crc = bit32.bxor(bit32.rshift(crc, 1), poly)
				else
					crc = bit32.rshift(crc, 1)
				end
			end
		else
			crc = bit32.bxor(crc, bit32.lshift(byte, width - 8))
			for _ = 1, 8 do
				if bit32.band(crc, bit32.lshift(1, width - 1)) ~= 0 then
					crc = bit32.bxor(bit32.band(bit32.lshift(crc, 1), mask), poly)
				else
					crc = bit32.band(bit32.lshift(crc, 1), mask)
				end
			end
		end
	end

	if refout ~= refin then
		crc = reflect_bits(crc, width)
	end

	crc = bit32.band(bit32.bxor(crc, preset.xorout), mask)
	return crc
end

local function crc_hex(s, preset_or_name)
	local preset = normalize_crc_preset(preset_or_name)
	local digits = math.ceil(preset.width / 4)
	return string.format("%0" .. tostring(digits) .. "x", crc_compute(s, preset))
end

local crc8 = function(s)
	return crc_hex(s, CRC_PRESETS.crc8)
end

local crc16 = function(s)
	return crc_hex(s, CRC_PRESETS.crc16)
end

local crc24 = function(s)
	return crc_hex(s, CRC_PRESETS.crc24)
end

local crc32 = function(s)
	return crc_hex(s, CRC_PRESETS.crc32)
end

local algorithms = {
	crc8 = crc8,
	crc16 = crc16,
	crc24 = crc24,
	crc32 = crc32,
}

return {
	crc = crc_hex,
	crc_value = crc_compute,
	crc8 = crc8,
	crc8_atm = crc8,
	crc16 = crc16,
	crc16_ibm = crc16,
	crc24 = crc24,
	crc24_openpgp = crc24,
	crc32 = crc32,
	crc32_ieee = crc32,
	presets = CRC_PRESETS,
	algorithms = algorithms,
}
