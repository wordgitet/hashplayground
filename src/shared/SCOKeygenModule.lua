--!strict
--!native
-- SPDX-License-Identifier: MIT
-- Hash Playground Rojo export.
-- Ported from the sb SCO serial utility by Amrit Panesar.
-- This module exposes the SCO serial, activation, license checksum, and registration key routines to the GUI.

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local MD5Module = require(ReplicatedStorage:WaitForChild("MD5Module"))

local ASCII_A = string.byte("a")
local FROM_HEXTET = "0123456789abcdefghjkmnpqrstuwxyz"
local REG_CHARMAP = "kbwtacorhzgsejqx"
local REG_SECRET = string.char(
	0x75, 0xF8, 0xE8, 0x5E, 0x83, 0xC4, 0x5E, 0x4C, 0xFF, 0x75,
	0x5E, 0x48, 0xE8, 0x65, 0x5E, 0x46, 0x59, 0x8B, 0x45
)
local EXT_SECRET = string.char(
	0x5E, 0x4F, 0xBE, 0x45, 0x5E, 0x4C, 0x8D, 0x40, 0x9F, 0xEB,
	0x26, 0x5E, 0x4F, 0xBE, 0x45, 0x5E, 0x4C, 0x3D, 0x30, 0x7C
)
local SERIAL_RANDOM = Random.new()

local CANON_ALPHA = {
	a = "a",
	b = "b",
	c = "c",
	d = "d",
	e = "e",
	f = "f",
	g = "g",
	h = "h",
	i = "1",
	j = "j",
	k = "k",
	l = "1",
	m = "m",
	n = "n",
	o = "0",
	p = "p",
	q = "q",
	r = "r",
	s = "s",
	t = "t",
	u = "u",
	v = "u",
	w = "w",
	x = "x",
	y = "y",
	z = "z",
}

local function md5_bytes(...)
	local parts = {...}
	local message = table.concat(parts)
	local hex_digest = MD5Module.hash(message)
	local bytes = table.create(#hex_digest // 2)

	for i = 1, #hex_digest, 2 do
		bytes[#bytes + 1] = tonumber(hex_digest:sub(i, i + 1), 16) :: number
	end

	return bytes
end

local function require_integer_in_range(value, minimum, maximum, field_name)
	if type(value) ~= "number" or value ~= math.floor(value) then
		error(field_name .. " must be an integer", 3)
	end
	if value < minimum or value > maximum then
		error(string.format("%s must be between %d and %d", field_name, minimum, maximum), 3)
	end
	return value
end

local function require_string(value, field_name)
	if type(value) ~= "string" then
		error(field_name .. " must be a string", 3)
	end
	return value
end

local function validate_serial_number(serial_number)
	serial_number = require_string(serial_number, "SCO serial number")
	if not serial_number:match("^SCO%d%d%d%d%d%d$") then
		error("SCO serial number must match SCO######", 3)
	end
	return serial_number
end

local function validate_host_id(host_id)
	host_id = require_string(host_id, "SCO host ID")
	if #host_id ~= 10 then
		error("SCO host ID must be 10 characters long", 3)
	end
	return host_id
end

local function bscanon(value)
	local output = table.create(#value)

	for i = 1, #value do
		local current = value:sub(i, i)
		local lower = string.lower(current)
		output[i] = CANON_ALPHA[lower] or current
	end

	return table.concat(output)
end

local function extmd(...)
	local digest = md5_bytes(...)
	local out = table.create(6)

	for index = 1, 6 do
		local alphabet_index = bit32.band(digest[index], 0x1F) + 1
		out[index] = FROM_HEXTET:sub(alphabet_index, alphabet_index)
	end

	return table.concat(out)
end

local function strbn(value)
	local chars = table.create(3)
	local remainder = value

	for index = 3, 1, -1 do
		local letter = (remainder % 26) + ASCII_A
		chars[index] = string.char(letter)
		remainder = math.floor(remainder / 26)
	end

	return table.concat(chars)
end

local function decfrp(value)
	local chars = table.create(#value)
	local carry = 0

	for index = #value, 1, -1 do
		local code = string.byte(value, index) :: number
		local shifted = ((code - ASCII_A) + carry) % 26
		local next_code = bit32.band(shifted + ASCII_A, 0xFF)
		carry = (carry + next_code) % 26
		chars[index] = string.char(next_code)
	end

	return table.concat(chars)
end

local function mnsnc(value)
	local accumulator = 0
	local rotate_count = (string.byte(value, 9) :: number) % 16

	for index = 1, #value do
		local current = string.byte(value, index) :: number
		local flag = (accumulator + current > 0x7FFF) and 1 or 0
		accumulator = bit32.bor(flag, bit32.band(2 * (accumulator + current), 0xFFFF))
	end

	for _ = 1, rotate_count do
		accumulator = bit32.bor(
			bit32.rshift(bit32.band(accumulator, 0x8000), 15),
			bit32.band(2 * accumulator, 0xFFFF)
		)
	end

	local second = string.char((accumulator % 26) + ASCII_A)
	accumulator = math.floor(accumulator / 26)
	local first = string.char((accumulator % 26) + ASCII_A)
	return first .. second
end

local function mkver(license_type, major, minor)
	return bit32.bor(bit32.lshift(license_type, 12), major * 10 + minor)
end

local function generate_serial_number()
	return string.format("SCO%06d", SERIAL_RANDOM:NextInteger(0, 0xEFFFF))
end

local function generate_activation_key_from_serial(serial_number, product_id, major, minor, has_license_data)
	validate_serial_number(serial_number)
	product_id = require_integer_in_range(product_id, 0, 17575, "SCO product ID")
	major = require_integer_in_range(major, 0, 409, "SCO major version")
	minor = require_integer_in_range(minor, 0, 9, "SCO minor version")

	local version = mkver(has_license_data and 3 or 2, major, minor)
	local base_key = strbn(product_id) .. strbn(version)
	local checksum = mnsnc(serial_number .. base_key)
	return decfrp(base_key .. checksum)
end

local function add_license_checksum(serial_number, activation_key, license_data)
	serial_number = validate_serial_number(serial_number)
	activation_key = require_string(activation_key, "SCO activation key")
	license_data = require_string(license_data, "SCO license data")

	if license_data == "" then
		error("SCO license data cannot be empty when adding a checksum", 2)
	end

	local canonical = bscanon(license_data)
	return license_data .. ";m" .. extmd(EXT_SECRET, serial_number, activation_key, canonical)
end

local function generate_snak(product_id, major, minor, license_data)
	local normalized_license_data = nil
	if license_data ~= nil and license_data ~= "" then
		normalized_license_data = require_string(license_data, "SCO license data")
	end

	local resolved_serial = generate_serial_number()

	local activation_key = generate_activation_key_from_serial(
		resolved_serial,
		product_id,
		major,
		minor,
		normalized_license_data ~= nil
	)

	local result = {
		serial_number = resolved_serial,
		activation_key = activation_key,
	}

	if normalized_license_data ~= nil then
		result.license_data = add_license_checksum(resolved_serial, activation_key, normalized_license_data)
	end

	return result
end

local function to_ascii_base16(input_value, checksum_base)
	local chars = table.create(10)
	local checksum = checksum_base
	local working = input_value

	for index = 8, 1, -1 do
		local nibble = 15 - bit32.band(working, 0xF)
		chars[index] = REG_CHARMAP:sub(nibble + 1, nibble + 1)
		checksum += nibble * index
		working = bit32.rshift(working, 4)
	end

	for index = 10, 9, -1 do
		local nibble = bit32.band(checksum, 0xF)
		chars[index] = REG_CHARMAP:sub(nibble + 1, nibble + 1)
		checksum = bit32.rshift(checksum, 4)
	end

	return table.concat(chars)
end

local function l32be(bytes)
	return bit32.bor(
		bit32.lshift(bytes[1], 24),
		bit32.lshift(bytes[2], 16),
		bit32.lshift(bytes[3], 8),
		bytes[4]
	)
end

local function generate_registration_key(serial_number, host_id)
	serial_number = validate_serial_number(serial_number)
	host_id = validate_host_id(host_id)

	local digest = md5_bytes(REG_SECRET, host_id, serial_number)
	local regkey = l32be(digest)
	return to_ascii_base16(regkey, 3)
end

local function is_valid_reglock(reglock)
	reglock = require_string(reglock, "SCO registration lock")

	local marker_start, marker_end = string.find(reglock, ";m", 1, true)
	if marker_start == nil or marker_end == nil then
		return false
	end
	if marker_end >= #reglock then
		return false
	end

	local prefix = reglock:sub(1, marker_start - 1)
	local checksum = reglock:sub(marker_end + 1)
	local canonical = bscanon(prefix)
	return extmd(REG_SECRET, canonical) == checksum
end

local function parse_reglock(reglock)
	reglock = require_string(reglock, "SCO registration lock")
	if not is_valid_reglock(reglock) then
		error("SCO registration lock is invalid; check for typos", 2)
	end

	local serial_number = nil
	local host_id = nil
	local prefix = reglock:match("^(.*);m")

	for field in string.gmatch(prefix :: string, "[^;]+") do
		local key = field:sub(1, 1)
		local value = field:sub(2)
		if key == "o" then
			serial_number = value
		elseif key == "u" then
			host_id = value
		end
	end

	if serial_number == nil or host_id == nil then
		error("SCO registration lock must contain both o<serial> and u<hostid> fields", 2)
	end

	return {
		serial_number = validate_serial_number(serial_number),
		host_id = validate_host_id(host_id),
	}
end

local function generate_registration_key_from_reglock(reglock)
	local parsed = parse_reglock(reglock)
	return generate_registration_key(parsed.serial_number, parsed.host_id)
end

return {
	from_hextet = FROM_HEXTET,
	generate_serial_number = generate_serial_number,
	generate_activation_key_from_serial = generate_activation_key_from_serial,
	add_license_checksum = add_license_checksum,
	generate_snak = generate_snak,
	generate_registration_key = generate_registration_key,
	generate_registration_key_from_reglock = generate_registration_key_from_reglock,
	parse_reglock = parse_reglock,
	is_valid_reglock = is_valid_reglock,
	bscanon = bscanon,
}
