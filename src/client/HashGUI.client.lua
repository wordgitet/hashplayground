-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- The entire UI is built in code so Rojo can sync a self-contained utility app without hand-maintained instances.

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local StarterGui = game:GetService("StarterGui")

local screen_gui = script.Parent
screen_gui.ResetOnSpawn = false
screen_gui.IgnoreGuiInset = true
screen_gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
screen_gui.DisplayOrder = 50

pcall(function()
	StarterGui.ScreenOrientation = Enum.ScreenOrientation.LandscapeSensor
end)

local function require_module(name)
	local ok, module = pcall(require, ReplicatedStorage:WaitForChild(name))
	if not ok then
		error("Failed to load " .. name .. ": " .. tostring(module))
	end
	return module
end

local md5_module = require_module("MD5Module")
local sha1_module = require_module("SHA1Module")
local sha256_module = require_module("SHA256Module")
local sha512_module = require_module("SHA512Module")
local sha3_module = require_module("SHA3Module")
local blake2b_module = require_module("BLAKE2bModule")
local blake3_module = require_module("BLAKE3Module")
local crc_module = require_module("CRCModule")
local hmac_module = require_module("HMACModule")
local pbkdf2_module = require_module("PBKDF2Module")
local sco_keygen_module = require_module("SCOKeygenModule")

local get_hash_output_length_value
local get_hash_function_name_value
local get_hash_customization_value

local hash_suite = {
	md5 = md5_module.hash or md5_module.md5,
	sha1 = sha1_module.hash or sha1_module.sha1,
	sha256 = sha256_module.hash or sha256_module.sha256,
	sha512 = sha512_module.hash or sha512_module.sha512,
	sha512_256 = sha512_module.sha512_256,
	sha512_224 = sha512_module.sha512_224,
	sha3_224 = sha3_module.sha3_224,
	sha3_256 = sha3_module.sha3_256,
	sha3_384 = sha3_module.sha3_384,
	sha3_512 = sha3_module.sha3_512,
	shake128 = function(input_text)
		return sha3_module.shake128(input_text, get_hash_output_length_value())
	end,
	shake256 = function(input_text)
		return sha3_module.shake256(input_text, get_hash_output_length_value())
	end,
	cshake128 = function(input_text)
		return sha3_module.cshake128(input_text, get_hash_output_length_value(), get_hash_function_name_value(), get_hash_customization_value())
	end,
	cshake256 = function(input_text)
		return sha3_module.cshake256(input_text, get_hash_output_length_value(), get_hash_function_name_value(), get_hash_customization_value())
	end,
	blake2b = blake2b_module.hash or blake2b_module.blake2b,
	blake3 = blake3_module.hash or blake3_module.blake3,
	crc8 = crc_module.crc8,
	crc16 = crc_module.crc16,
	crc24 = crc_module.crc24,
	crc32 = crc_module.crc32,
}

local hmac_digest_modules = {
	sha1 = sha1_module,
	sha256 = sha256_module,
	sha512 = sha512_module,
}

local encoding_service = nil
local native_hash_algorithms = {}
do
	local ok_service, service = pcall(game.GetService, game, "EncodingService")
	if ok_service then
		encoding_service = service
	end

	local ok_sha1, sha1_algorithm = pcall(function()
		return Enum.HashAlgorithm.Sha1
	end)
	if ok_sha1 then
		native_hash_algorithms.sha1 = sha1_algorithm
	end

	local ok_sha256, sha256_algorithm = pcall(function()
		return Enum.HashAlgorithm.Sha256
	end)
	if ok_sha256 then
		native_hash_algorithms.sha256 = sha256_algorithm
	end

	local ok_blake3, blake3_algorithm = pcall(function()
		return Enum.HashAlgorithm.Blake3
	end)
	if ok_blake3 then
		native_hash_algorithms.blake3 = blake3_algorithm
	end
end

local algorithm_labels = {
	md5 = "MD5",
	sha1 = "SHA-1",
	sha256 = "SHA-256",
	sha512 = "SHA-512",
	sha512_256 = "SHA-512/256",
	sha512_224 = "SHA-512/224",
	sha3_224 = "SHA3-224",
	sha3_256 = "SHA3-256",
	sha3_384 = "SHA3-384",
	sha3_512 = "SHA3-512",
	shake128 = "SHAKE128",
	shake256 = "SHAKE256",
	cshake128 = "cSHAKE128",
	cshake256 = "cSHAKE256",
	blake2b = "BLAKE2b",
	blake3 = "BLAKE3",
	crc8 = "CRC-8",
	crc16 = "CRC-16",
	crc24 = "CRC-24",
	crc32 = "CRC-32",
}

local algorithm_order = {"md5", "sha1", "sha256", "sha512", "sha512_256", "sha512_224", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256", "cshake128", "cshake256", "blake2b", "blake3", "crc8", "crc16", "crc24", "crc32"}
local backend_labels = {
	custom = "Custom",
	native = "Native",
}
local digest_labels = {
	sha1 = "SHA-1",
	sha256 = "SHA-256",
	sha512 = "SHA-512",
}
local digest_order = {"sha1", "sha256", "sha512"}

local palette = {
	background = Color3.fromRGB(42, 42, 46),
	sidebar = Color3.fromRGB(48, 48, 53),
	panel = Color3.fromRGB(50, 50, 56),
	surface = Color3.fromRGB(58, 58, 64),
	surface_soft = Color3.fromRGB(52, 52, 58),
	selected = Color3.fromRGB(49, 136, 209),
	accent = Color3.fromRGB(66, 145, 214),
	accent_soft = Color3.fromRGB(84, 161, 228),
	border = Color3.fromRGB(74, 74, 80),
	text = Color3.fromRGB(240, 240, 244),
	muted = Color3.fromRGB(206, 209, 215),
	subtle = Color3.fromRGB(157, 161, 170),
	success = Color3.fromRGB(102, 210, 143),
	danger = Color3.fromRGB(235, 96, 102),
	result = Color3.fromRGB(232, 235, 240),
}

local current_mode = "hash"
local current_algorithm = "md5"
local current_backend_mode = "custom"
local current_hmac_digest = "sha256"
local current_pbkdf2_digest = "sha256"
local current_result_value = ""
local current_status_text = "Ready"
local current_status_color = palette.success

local mode_rows = {}
local algorithm_rows = {}
local digest_rows = {}
local backend_rows = {}

local sidebar_algorithm_section
local sidebar_digest_section
local sidebar_backend_section
local backend_note_label
local native_row
local sidebar
local sidebar_inner
local sidebar_padding
local sidebar_title_label
local sidebar_subtitle_label
local workspace_title
local workspace_subtitle
local workspace
local workspace_padding
local result_box_padding
local hash_workspace
local hmac_workspace
local kmac_workspace
local pbkdf2_workspace
local sco_snak_workspace
local sco_reg_workspace
local hash_input_box
local hash_output_length_box
local hash_output_length_field
local hash_function_name_box
local hash_function_name_field
local hash_customization_box
local hash_customization_field
local hmac_key_box
local hmac_message_box
local kmac_key_box
local kmac_message_box
local kmac_customization_box
local kmac_output_length_box
local pbkdf2_password_box
local pbkdf2_salt_box
local pbkdf2_iterations_box
local pbkdf2_length_box
local sco_product_id_box
local sco_major_box
local sco_minor_box
local sco_license_box
local sco_reg_serial_box
local sco_host_id_box
local sco_reglock_box
local result_title
local result_meta_label
local result_box
local status_dot
local status_label
local summary_mode_value
local summary_target_value
local summary_engine_value
local hash_generate_button
local hash_clear_button
local hmac_generate_button
local hmac_clear_button
local kmac_generate_button
local kmac_clear_button
local pbkdf2_generate_button
local pbkdf2_clear_button
local sco_snak_generate_button
local sco_snak_clear_button
local sco_reg_generate_button
local sco_reg_clear_button
local shell_padding
local body_layout
local hash_action_row

local function make(class_name, properties, parent)
	local instance = Instance.new(class_name)
	for key, value in pairs(properties or {}) do
		instance[key] = value
	end
	if parent then
		instance.Parent = parent
	end
	return instance
end

local function add_corner(instance, radius)
	make("UICorner", {
		CornerRadius = UDim.new(0, radius or 8),
	}, instance)
end

local function add_stroke(instance, color, thickness, transparency)
	make("UIStroke", {
		Color = color,
		Thickness = thickness or 1,
		Transparency = transparency or 0.4,
	}, instance)
end

local function bind_canvas_size(scroller, layout, extra_height)
	local function update_canvas()
		scroller.CanvasSize = UDim2.new(0, 0, 0, layout.AbsoluteContentSize.Y + (extra_height or 4))
	end
	layout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(update_canvas)
	update_canvas()
end

local function get_algorithm_label(algorithm_key)
	return algorithm_labels[algorithm_key] or string.upper(algorithm_key)
end

local function get_digest_label(digest_key)
	return digest_labels[digest_key] or string.upper(digest_key)
end

local function get_backend_label(backend_key)
	return backend_labels[backend_key] or string.upper(backend_key)
end

local function get_text_value(text_box, fallback)
	if text_box and text_box.Text ~= "" then
		return text_box.Text
	end
	return fallback or ""
end

local function get_sco_version_summary()
	local product_id = get_text_value(sco_product_id_box, "?")
	local major = get_text_value(sco_major_box, "?")
	local minor = get_text_value(sco_minor_box, "?")
	return "Product " .. product_id .. "  |  Version " .. major .. "." .. minor
end

local function is_shake_algorithm(algorithm_key)
	return algorithm_key == "shake128" or algorithm_key == "shake256"
end

local function is_cshake_algorithm(algorithm_key)
	return algorithm_key == "cshake128" or algorithm_key == "cshake256"
end

local function hash_algorithm_supports_output_length(algorithm_key)
	return is_shake_algorithm(algorithm_key) or is_cshake_algorithm(algorithm_key)
end

local function get_default_hash_output_length(algorithm_key)
	if algorithm_key == "shake256" or algorithm_key == "cshake256" then
		return "64"
	elseif algorithm_key == "shake128" or algorithm_key == "cshake128" then
		return "32"
	end
	return ""
end

local function get_default_kmac_output_length(mode_key)
	if mode_key == "kmac256" then
		return "64"
	end
	return "32"
end

get_hash_output_length_value = function()
	local default_length = tonumber(get_default_hash_output_length(current_algorithm)) or 32
	local length_value = tonumber(hash_output_length_box and hash_output_length_box.Text or "")
	if not length_value then
		return default_length
	end
	return length_value
end

get_hash_function_name_value = function()
	return hash_function_name_box and hash_function_name_box.Text or ""
end

get_hash_customization_value = function()
	return hash_customization_box and hash_customization_box.Text or ""
end

local function is_native_backend_supported(algorithm_key)
	return encoding_service ~= nil and native_hash_algorithms[algorithm_key] ~= nil
end

local function normalize_native_hash(native_hash)
	if type(native_hash) ~= "string" then
		return tostring(native_hash)
	end

	local lowered = string.lower(native_hash)
	if (#lowered == 40 or #lowered == 64) and lowered:match("^[0-9a-f]+$") then
		return lowered
	end

	if #native_hash == 20 or #native_hash == 32 then
		local hex_parts = table.create(#native_hash)
		for i = 1, #native_hash do
			hex_parts[i] = string.format("%02x", string.byte(native_hash, i))
		end
		return table.concat(hex_parts)
	end

	return lowered
end

local function get_hash_function()
	local native_algorithm = native_hash_algorithms[current_algorithm]
	if current_backend_mode == "native" and native_algorithm and encoding_service then
		return function(input_text)
			local ok, native_hash = pcall(function()
				return encoding_service:ComputeStringHash(input_text, native_algorithm)
			end)
			if not ok then
				error(native_hash, 2)
			end
			return normalize_native_hash(native_hash)
		end
	end

	return hash_suite[current_algorithm] or hash_suite.md5
end

local function create_section_frame(parent, layout_order, height)
	return make("Frame", {
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		LayoutOrder = layout_order,
		Size = UDim2.new(1, 0, 0, height),
	}, parent)
end

local function create_section_label(parent, text)
	return make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Size = UDim2.new(1, 0, 0, 15),
		Text = text,
		TextColor3 = palette.subtle,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, parent)
end

local function style_row(button, active, enabled)
	button.Active = enabled
	button.AutoButtonColor = false
	button.BackgroundColor3 = active and palette.selected or palette.surface_soft
	button.BackgroundTransparency = active and 0 or (enabled and 1 or 0.55)

	local label = button:FindFirstChild("label")
	local accent = button:FindFirstChild("accent")
	local stroke = button:FindFirstChildOfClass("UIStroke")

	if label then
		label.TextColor3 = active and palette.text or (enabled and palette.muted or palette.subtle)
		label.Font = active and Enum.Font.GothamSemibold or Enum.Font.GothamMedium
	end

	if accent then
		accent.Visible = active
	end

	if stroke then
		stroke.Transparency = active and 0.65 or 1
	end
end

local function create_row_button(parent, text, layout_order)
	local button = make("TextButton", {
		AutoButtonColor = false,
		BackgroundColor3 = palette.selected,
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		LayoutOrder = layout_order,
		Size = UDim2.new(1, 0, 0, 32),
		Text = "",
	}, parent)
	add_corner(button, 6)
	add_stroke(button, palette.border, 1, 1)

	make("UIPadding", {
		PaddingLeft = UDim.new(0, 12),
		PaddingRight = UDim.new(0, 10),
	}, button)

	local accent = make("Frame", {
		Name = "accent",
		AnchorPoint = Vector2.new(0, 0.5),
		BackgroundColor3 = palette.accent,
		BorderSizePixel = 0,
		Position = UDim2.new(0, 0, 0.5, 0),
		Size = UDim2.new(0, 3, 0, 16),
		Visible = false,
	}, button)
	add_corner(accent, 999)

	make("TextLabel", {
		Name = "label",
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 10, 0, 0),
		Size = UDim2.new(1, -10, 1, 0),
		Text = text,
		TextColor3 = palette.muted,
		TextSize = 12,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, button)

	return button
end

local function create_field(parent, title, placeholder, multiline, height, secret)
	local holder = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, height + 20),
	}, parent)

	create_section_label(holder, title)

	local text_box = make("TextBox", {
		BackgroundColor3 = palette.surface,
		BorderSizePixel = 0,
		ClearTextOnFocus = false,
		Font = Enum.Font.GothamMedium,
		MultiLine = multiline == true,
		PlaceholderColor3 = palette.subtle,
		PlaceholderText = placeholder,
		Position = UDim2.new(0, 0, 0, 22),
		Size = UDim2.new(1, 0, 0, height),
		Text = "",
		TextColor3 = palette.text,
		TextSize = 14,
		TextWrapped = multiline == true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = multiline == true and Enum.TextYAlignment.Top or Enum.TextYAlignment.Center,
	}, holder)
	text_box:SetAttribute("secret", secret == true)
	if secret then
		text_box.Text = ""
	end
	add_corner(text_box, 4)
	add_stroke(text_box, palette.border, 1, 0.62)

	make("UIPadding", {
		PaddingLeft = UDim.new(0, 12),
		PaddingRight = UDim.new(0, 12),
		PaddingTop = UDim.new(0, multiline and 10 or 0),
	}, text_box)

	return holder, text_box
end

local function create_action_button(parent, text, primary, size)
	local button = make("TextButton", {
		AutoButtonColor = false,
		BackgroundColor3 = primary and palette.accent or palette.surface,
		BorderSizePixel = 0,
		Font = primary and Enum.Font.GothamSemibold or Enum.Font.GothamMedium,
		Size = size,
		Text = text,
		TextColor3 = primary and Color3.fromRGB(255, 255, 255) or palette.text,
		TextSize = 14,
	}, parent)
	add_corner(button, 6)
	add_stroke(button, primary and palette.accent_soft or palette.border, 1, primary and 0.5 or 0.75)
	return button
end

local existing_root = screen_gui:FindFirstChild("hash_playground_root")
if existing_root then
	existing_root:Destroy()
end

local root = make("Frame", {
	Name = "hash_playground_root",
	BackgroundColor3 = palette.background,
	BorderSizePixel = 0,
	Size = UDim2.fromScale(1, 1),
}, screen_gui)

make("Frame", {
	BackgroundColor3 = palette.accent,
	BackgroundTransparency = 0.2,
	BorderSizePixel = 0,
	Size = UDim2.new(1, 0, 0, 2),
}, root)

local shell = make("Frame", {
	BackgroundTransparency = 1,
	BorderSizePixel = 0,
	Position = UDim2.new(0, 0, 0, 2),
	Size = UDim2.new(1, 0, 1, -2),
}, root)
shell_padding = make("UIPadding", {
	PaddingBottom = UDim.new(0, 10),
	PaddingLeft = UDim.new(0, 10),
	PaddingRight = UDim.new(0, 10),
	PaddingTop = UDim.new(0, 10),
}, shell)

local body = make("Frame", {
	BackgroundTransparency = 1,
	BorderSizePixel = 0,
	Size = UDim2.fromScale(1, 1),
}, shell)
body_layout = make("UIListLayout", {
	FillDirection = Enum.FillDirection.Horizontal,
	Padding = UDim.new(0, 10),
	SortOrder = Enum.SortOrder.LayoutOrder,
	VerticalAlignment = Enum.VerticalAlignment.Top,
}, body)

local function create_divider(parent, layout_order)
	return make("Frame", {
		BackgroundColor3 = palette.border,
		BackgroundTransparency = 0.35,
		BorderSizePixel = 0,
		LayoutOrder = layout_order,
		Size = UDim2.new(1, 0, 0, 1),
	}, parent)
end

sidebar = make("Frame", {
	BackgroundColor3 = palette.sidebar,
	BorderSizePixel = 0,
	LayoutOrder = 1,
	Size = UDim2.new(0, 232, 1, 0),
}, body)
add_corner(sidebar, 2)
add_stroke(sidebar, palette.border, 1, 0.7)

sidebar_inner = make("ScrollingFrame", {
	Active = true,
	AutomaticCanvasSize = Enum.AutomaticSize.None,
	BackgroundTransparency = 1,
	BorderSizePixel = 0,
	CanvasSize = UDim2.new(0, 0, 0, 0),
	ScrollBarImageColor3 = palette.border,
	ScrollBarThickness = 4,
	ScrollingDirection = Enum.ScrollingDirection.Y,
	Size = UDim2.fromScale(1, 1),
}, sidebar)
sidebar_padding = make("UIPadding", {
	PaddingBottom = UDim.new(0, 14),
	PaddingLeft = UDim.new(0, 14),
	PaddingRight = UDim.new(0, 14),
	PaddingTop = UDim.new(0, 14),
}, sidebar_inner)
local sidebar_layout = make("UIListLayout", {
	Padding = UDim.new(0, 10),
	SortOrder = Enum.SortOrder.LayoutOrder,
}, sidebar_inner)
bind_canvas_size(sidebar_inner, sidebar_layout, 32)

local sidebar_header = make("Frame", {
	BackgroundTransparency = 1,
	LayoutOrder = 1,
	Size = UDim2.new(1, 0, 0, 62),
}, sidebar_inner)
sidebar_title_label = make("TextLabel", {
	BackgroundTransparency = 1,
	Font = Enum.Font.GothamSemibold,
	Size = UDim2.new(1, 0, 0, 26),
	Text = "Checksum Playground",
	TextColor3 = palette.text,
	TextSize = 20,
	TextXAlignment = Enum.TextXAlignment.Left,
}, sidebar_header)
sidebar_subtitle_label = make("TextLabel", {
	BackgroundTransparency = 1,
	Font = Enum.Font.GothamMedium,
	Position = UDim2.new(0, 0, 0, 28),
	Size = UDim2.new(1, 0, 0, 28),
	Text = "GTK-style utility shell for hashes, key derivation, and SCO licensing tools",
	TextColor3 = palette.subtle,
	TextSize = 11,
	TextWrapped = true,
	TextXAlignment = Enum.TextXAlignment.Left,
	TextYAlignment = Enum.TextYAlignment.Top,
}, sidebar_header)
create_divider(sidebar_inner, 2)

do
	local mode_options = {
		{key = "hash", label = "Hash"},
		{key = "hmac", label = "HMAC"},
		{key = "kmac128", label = "KMAC128"},
		{key = "kmac256", label = "KMAC256"},
		{key = "pbkdf2", label = "PBKDF2"},
		{key = "sco_snak", label = "SCO SNAK"},
		{key = "sco_reg", label = "SCO Reg"},
	}
	local mode_section_height = 22 + (#mode_options * 32) + ((#mode_options - 1) * 4)
	local mode_section = create_section_frame(sidebar_inner, 3, mode_section_height)
	create_section_label(mode_section, "Mode")
	local mode_rows_holder = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 22),
		Size = UDim2.new(1, 0, 1, -22),
	}, mode_section)
	make("UIListLayout", {
		Padding = UDim.new(0, 4),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, mode_rows_holder)
	for index, mode_data in ipairs(mode_options) do
		local row = create_row_button(mode_rows_holder, mode_data.label, index)
		mode_rows[mode_data.key] = row
	end
	create_divider(sidebar_inner, 4)
end

do
	sidebar_algorithm_section = create_section_frame(sidebar_inner, 5, 252)
	create_section_label(sidebar_algorithm_section, "Algorithms")
	local algorithm_scroller = make("ScrollingFrame", {
		Active = true,
		AutomaticCanvasSize = Enum.AutomaticSize.None,
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		CanvasSize = UDim2.new(0, 0, 0, 0),
		Position = UDim2.new(0, 0, 0, 22),
		ScrollBarImageColor3 = palette.border,
		ScrollBarThickness = 4,
		Size = UDim2.new(1, 0, 1, -22),
	}, sidebar_algorithm_section)
	local algorithm_rows_holder = make("Frame", {
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		Size = UDim2.new(1, -6, 0, 0),
	}, algorithm_scroller)
	local algorithm_layout = make("UIListLayout", {
		Padding = UDim.new(0, 4),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, algorithm_rows_holder)
	bind_canvas_size(algorithm_scroller, algorithm_layout)
	for index, algorithm_key in ipairs(algorithm_order) do
		local row = create_row_button(algorithm_rows_holder, get_algorithm_label(algorithm_key), index)
		algorithm_rows[algorithm_key] = row
	end
end

do
	sidebar_digest_section = create_section_frame(sidebar_inner, 6, 122)
	create_section_label(sidebar_digest_section, "Digest")
	local digest_rows_holder = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 22),
		Size = UDim2.new(1, 0, 1, -22),
	}, sidebar_digest_section)
	make("UIListLayout", {
		Padding = UDim.new(0, 4),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, digest_rows_holder)
	for index, digest_key in ipairs(digest_order) do
		local row = create_row_button(digest_rows_holder, get_digest_label(digest_key), index)
		digest_rows[digest_key] = row
	end
	create_divider(sidebar_inner, 7)
end

do
	sidebar_backend_section = create_section_frame(sidebar_inner, 8, 122)
	create_section_label(sidebar_backend_section, "Backend")
	local backend_rows_holder = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 22),
		Size = UDim2.new(1, 0, 0, 68),
	}, sidebar_backend_section)
	make("UIListLayout", {
		Padding = UDim.new(0, 4),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, backend_rows_holder)
	backend_rows.custom = create_row_button(backend_rows_holder, "Custom", 1)
	native_row = create_row_button(backend_rows_holder, "Native", 2)
	backend_rows.native = native_row
	backend_note_label = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 0, 0, 92),
		Size = UDim2.new(1, 0, 0, 24),
		Text = "Native works with SHA-1, SHA-256, and BLAKE3.",
		TextColor3 = palette.subtle,
		TextSize = 10,
		TextWrapped = true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
	}, sidebar_backend_section)
	create_divider(sidebar_inner, 9)
end

local function create_summary_row(parent, layout_order, label_text)
	local row = make("Frame", {
		BackgroundTransparency = 1,
		LayoutOrder = layout_order,
		Size = UDim2.new(1, 0, 0, 16),
	}, parent)
	make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Size = UDim2.new(0, 54, 1, 0),
		Text = label_text,
		TextColor3 = palette.subtle,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, row)
	return make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 58, 0, 0),
		Size = UDim2.new(1, -58, 1, 0),
		Text = "",
		TextColor3 = palette.text,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, row)
end
do
	local summary_section = create_section_frame(sidebar_inner, 10, 98)
	create_section_label(summary_section, "Current State")
	local summary_holder = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 24),
		Size = UDim2.new(1, 0, 1, -24),
	}, summary_section)
	make("UIListLayout", {
		Padding = UDim.new(0, 8),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, summary_holder)
	summary_mode_value = create_summary_row(summary_holder, 1, "Mode")
	summary_target_value = create_summary_row(summary_holder, 2, "Target")
	summary_engine_value = create_summary_row(summary_holder, 3, "Engine")
end

workspace = make("ScrollingFrame", {
	Active = true,
	AutomaticCanvasSize = Enum.AutomaticSize.None,
	BackgroundColor3 = palette.panel,
	BorderSizePixel = 0,
	CanvasSize = UDim2.new(0, 0, 0, 0),
	LayoutOrder = 2,
	ScrollBarImageColor3 = palette.border,
	ScrollBarThickness = 4,
	ScrollingDirection = Enum.ScrollingDirection.Y,
	Size = UDim2.new(1, -242, 1, 0),
}, body)
add_corner(workspace, 2)
add_stroke(workspace, palette.border, 1, 0.72)
workspace_padding = make("UIPadding", {
	PaddingBottom = UDim.new(0, 16),
	PaddingLeft = UDim.new(0, 16),
	PaddingRight = UDim.new(0, 16),
	PaddingTop = UDim.new(0, 14),
}, workspace)
local workspace_layout = make("UIListLayout", {
	Padding = UDim.new(0, 12),
	SortOrder = Enum.SortOrder.LayoutOrder,
}, workspace)
bind_canvas_size(workspace, workspace_layout, 36)

do
	local header_panel = create_section_frame(workspace, 1, 58)
	workspace_title = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamSemibold,
		Size = UDim2.new(1, 0, 0, 24),
		Text = "Hash",
		TextColor3 = palette.text,
		TextSize = 22,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, header_panel)
	workspace_subtitle = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 0, 0, 26),
		Size = UDim2.new(1, 0, 0, 28),
		Text = "Generate a digest from any input string.",
		TextColor3 = palette.subtle,
		TextSize = 12,
		TextWrapped = true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
	}, header_panel)
end
create_divider(workspace, 2)

do
	hash_workspace = create_section_frame(workspace, 3, 228)
	local _, hash_input = create_field(hash_workspace, "Input", "Type or paste text to hash", true, 104, false)
	hash_input_box = hash_input
	hash_input.Position = UDim2.new(0, 0, 0, 0)
	local hash_options_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 126),
		Size = UDim2.new(1, 0, 0, 198),
	}, hash_workspace)
	hash_output_length_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(0.5, -6, 0, 60),
		Visible = false,
	}, hash_options_row)
	local _, output_length_box = create_field(hash_output_length_field, "Output bytes", "32", false, 40, false)
	hash_output_length_box = output_length_box
	hash_output_length_box.Text = "32"
	hash_function_name_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 60),
		Visible = false,
	}, hash_options_row)
	local _, function_name_box = create_field(hash_function_name_field, "Function name", "Optional: app name", false, 40, false)
	hash_function_name_box = function_name_box
	hash_customization_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 60),
		Visible = false,
	}, hash_options_row)
	local _, customization_box = create_field(hash_customization_field, "Customization", "Optional: domain string", false, 40, false)
	hash_customization_box = customization_box
	hash_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 192),
		Size = UDim2.new(1, 0, 0, 36),
	}, hash_workspace)
	hash_generate_button = create_action_button(hash_action_row, "Generate Hash", true, UDim2.new(0, 164, 1, 0))
	hash_clear_button = create_action_button(hash_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	hash_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

do
	hmac_workspace = create_section_frame(workspace, 4, 252)
	local hmac_fields = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 186),
	}, hmac_workspace)
	local hmac_key_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 78),
	}, hmac_fields)
	local _, hmac_key_input = create_field(hmac_key_field, "Key", "Enter secret key", false, 40, true)
	hmac_key_box = hmac_key_input
	local hmac_message_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 88),
		Size = UDim2.new(1, 0, 0, 98),
	}, hmac_fields)
	local _, hmac_message_input = create_field(hmac_message_field, "Message", "Type or paste text to authenticate", true, 90, false)
	hmac_message_box = hmac_message_input
	local hmac_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -36),
		Size = UDim2.new(1, 0, 0, 36),
	}, hmac_workspace)
	hmac_generate_button = create_action_button(hmac_action_row, "Generate MAC", true, UDim2.new(0, 164, 1, 0))
	hmac_clear_button = create_action_button(hmac_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	hmac_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

do
	kmac_workspace = create_section_frame(workspace, 5, 322)
	local kmac_fields = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 256),
	}, kmac_workspace)
	local kmac_key_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 78),
	}, kmac_fields)
	local _, kmac_key_input = create_field(kmac_key_field, "Key", "Enter secret key", false, 40, true)
	kmac_key_box = kmac_key_input
	local kmac_message_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 88),
		Size = UDim2.new(1, 0, 0, 98),
	}, kmac_fields)
	local _, kmac_message_input = create_field(kmac_message_field, "Message", "Type or paste text to authenticate", true, 90, false)
	kmac_message_box = kmac_message_input
	local kmac_options_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 196),
		Size = UDim2.new(1, 0, 0, 60),
	}, kmac_fields)
	local kmac_custom_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(0.68, -6, 1, 0),
	}, kmac_options_row)
	local _, kmac_custom_input = create_field(kmac_custom_field, "Customization", "Optional: domain string", false, 40, false)
	kmac_customization_box = kmac_custom_input
	local kmac_output_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0.68, 6, 0, 0),
		Size = UDim2.new(0.32, -6, 1, 0),
	}, kmac_options_row)
	local _, kmac_length_input = create_field(kmac_output_field, "Output bytes", "32", false, 40, false)
	kmac_output_length_box = kmac_length_input
	kmac_output_length_box.Text = "32"
	local kmac_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -36),
		Size = UDim2.new(1, 0, 0, 36),
	}, kmac_workspace)
	kmac_generate_button = create_action_button(kmac_action_row, "Generate KMAC", true, UDim2.new(0, 164, 1, 0))
	kmac_clear_button = create_action_button(kmac_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	kmac_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

do
	pbkdf2_workspace = create_section_frame(workspace, 6, 238)
	local pbkdf2_fields = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 172),
	}, pbkdf2_workspace)
	local top_row = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 78),
	}, pbkdf2_fields)
	local password_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(0.5, -6, 1, 0),
	}, top_row)
	local _, password_box = create_field(password_field, "Password", "Enter password", false, 40, true)
	pbkdf2_password_box = password_box
	local salt_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0.5, 6, 0, 0),
		Size = UDim2.new(0.5, -6, 1, 0),
	}, top_row)
	local _, salt_box = create_field(salt_field, "Salt", "Enter salt", false, 40, false)
	pbkdf2_salt_box = salt_box
	local bottom_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 88),
		Size = UDim2.new(1, 0, 0, 78),
	}, pbkdf2_fields)
	local iterations_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(0.5, -6, 1, 0),
	}, bottom_row)
	local _, iterations_box = create_field(iterations_field, "Iterations", "1000", false, 40, false)
	iterations_box.Text = "1000"
	pbkdf2_iterations_box = iterations_box
	local length_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0.5, 6, 0, 0),
		Size = UDim2.new(0.5, -6, 1, 0),
	}, bottom_row)
	local _, length_box = create_field(length_field, "Derived key length", "32", false, 40, false)
	length_box.Text = "32"
	pbkdf2_length_box = length_box
	local pbkdf2_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -36),
		Size = UDim2.new(1, 0, 0, 36),
	}, pbkdf2_workspace)
	pbkdf2_generate_button = create_action_button(pbkdf2_action_row, "Derive Key", true, UDim2.new(0, 164, 1, 0))
	pbkdf2_clear_button = create_action_button(pbkdf2_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	pbkdf2_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

do
	sco_snak_workspace = create_section_frame(workspace, 7, 238)
	local sco_snak_fields = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 172),
	}, sco_snak_workspace)
	local sco_version_row = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 78),
	}, sco_snak_fields)
	local product_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1 / 3, -8, 1, 0),
	}, sco_version_row)
	local _, product_id_box = create_field(product_field, "Product ID", "203", false, 40, false)
	sco_product_id_box = product_id_box
	local major_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(1 / 3, 4, 0, 0),
		Size = UDim2.new(1 / 3, -8, 1, 0),
	}, sco_version_row)
	local _, major_box = create_field(major_field, "Major", "71", false, 40, false)
	sco_major_box = major_box
	local minor_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(2 / 3, 8, 0, 0),
		Size = UDim2.new(1 / 3, -8, 1, 0),
	}, sco_version_row)
	local _, minor_box = create_field(minor_field, "Minor", "4", false, 40, false)
	sco_minor_box = minor_box
	local license_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 88),
		Size = UDim2.new(1, 0, 0, 78),
	}, sco_snak_fields)
	local _, license_box = create_field(license_field, "License data", "Optional: c4;u100", false, 40, false)
	sco_license_box = license_box
	local sco_snak_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -36),
		Size = UDim2.new(1, 0, 0, 36),
	}, sco_snak_workspace)
	sco_snak_generate_button = create_action_button(sco_snak_action_row, "Generate SNAK", true, UDim2.new(0, 164, 1, 0))
	sco_snak_clear_button = create_action_button(sco_snak_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	sco_snak_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

do
	sco_reg_workspace = create_section_frame(workspace, 8, 256)
	local sco_reg_fields = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 190),
	}, sco_reg_workspace)
	local sco_reg_top_row = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(1, 0, 0, 78),
	}, sco_reg_fields)
	local reg_serial_field = make("Frame", {
		BackgroundTransparency = 1,
		Size = UDim2.new(0.5, -6, 1, 0),
	}, sco_reg_top_row)
	local _, reg_serial_box = create_field(reg_serial_field, "Serial number", "SCO123456", false, 40, false)
	sco_reg_serial_box = reg_serial_box
	local host_id_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0.5, 6, 0, 0),
		Size = UDim2.new(0.5, -6, 1, 0),
	}, sco_reg_top_row)
	local _, host_id_box = create_field(host_id_field, "Host ID", "orxrrwjwxz", false, 40, false)
	sco_host_id_box = host_id_box
	local reglock_field = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 0, 88),
		Size = UDim2.new(1, 0, 0, 78),
	}, sco_reg_fields)
	local _, reglock_box = create_field(reglock_field, "Registration lock", "Optional: oSCO123456;u1234567890;m......", false, 40, false)
	sco_reglock_box = reglock_box
	make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 0, 0, 168),
		Size = UDim2.new(1, 0, 0, 20),
		Text = "Paste a reglock or provide serial number plus host ID.",
		TextColor3 = palette.subtle,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, sco_reg_fields)
	local sco_reg_action_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -36),
		Size = UDim2.new(1, 0, 0, 36),
	}, sco_reg_workspace)
	sco_reg_generate_button = create_action_button(sco_reg_action_row, "Generate Key", true, UDim2.new(0, 164, 1, 0))
	sco_reg_clear_button = create_action_button(sco_reg_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
	sco_reg_clear_button.Position = UDim2.new(0, 174, 0, 0)
end

create_divider(workspace, 9)

do
	local result_panel = create_section_frame(workspace, 10, 210)
	result_title = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamSemibold,
		Size = UDim2.new(1, 0, 0, 18),
		Text = "Result",
		TextColor3 = palette.text,
		TextSize = 14,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, result_panel)
	result_meta_label = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 0, 0, 20),
		Size = UDim2.new(1, 0, 0, 18),
		Text = "",
		TextColor3 = palette.subtle,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, result_panel)
	result_box = make("TextBox", {
		BackgroundColor3 = palette.surface,
		BorderSizePixel = 0,
		ClearTextOnFocus = false,
		Font = Enum.Font.Code,
		Position = UDim2.new(0, 0, 0, 44),
		Selectable = true,
		Size = UDim2.new(1, 0, 0, 128),
		Text = "The output will appear here",
		TextColor3 = palette.subtle,
		TextEditable = false,
		TextSize = 14,
		TextWrapped = true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
	}, result_panel)
	add_corner(result_box, 3)
	add_stroke(result_box, palette.border, 1, 0.72)
	result_box_padding = make("UIPadding", {
		PaddingBottom = UDim.new(0, 12),
		PaddingLeft = UDim.new(0, 12),
		PaddingRight = UDim.new(0, 12),
		PaddingTop = UDim.new(0, 10),
	}, result_box)
	local status_row = make("Frame", {
		BackgroundTransparency = 1,
		Position = UDim2.new(0, 0, 1, -18),
		Size = UDim2.new(1, 0, 0, 18),
	}, result_panel)
	status_dot = make("Frame", {
		AnchorPoint = Vector2.new(0, 0.5),
		BackgroundColor3 = palette.success,
		BorderSizePixel = 0,
		Position = UDim2.new(0, 0, 0.5, 0),
		Size = UDim2.new(0, 8, 0, 8),
	}, status_row)
	add_corner(status_dot, 999)
	status_label = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = Enum.Font.GothamMedium,
		Position = UDim2.new(0, 16, 0, 0),
		Size = UDim2.new(1, -16, 1, 0),
		Text = "Ready",
		TextColor3 = palette.success,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
	}, status_row)
end

local RESULT_PLACEHOLDER = "The output will appear here"

local mode_configs

local function get_default_pbkdf2_length()
	return current_pbkdf2_digest == "sha512" and "64" or "32"
end

local function get_current_digest_key()
	if current_mode == "hmac" then
		return current_hmac_digest
	end
	if current_mode == "pbkdf2" then
		return current_pbkdf2_digest
	end
	return nil
end

local function mode_allows_digest(config, digest_key)
	local allowed_digests = config.allowed_digests
	if type(allowed_digests) ~= "table" then
		return false
	end
	return table.find(allowed_digests, digest_key) ~= nil
end

local function update_row_button_density(rows, compact)
	for _, row in pairs(rows) do
		row.Size = UDim2.new(1, 0, 0, compact and 28 or 32)

		local label = row:FindFirstChild("label")
		if label and label:IsA("TextLabel") then
			label.TextSize = compact and 11 or 12
		end

		local accent = row:FindFirstChild("accent")
		if accent and accent:IsA("Frame") then
			accent.Size = UDim2.new(0, 3, 0, compact and 14 or 16)
		end
	end
end

local function update_action_button_density(primary_button, secondary_button, compact)
	local primary_width = compact and 144 or 164
	local secondary_width = compact and 96 or 110
	primary_button.Size = UDim2.new(0, primary_width, 1, 0)
	secondary_button.Size = UDim2.new(0, secondary_width, 1, 0)
	secondary_button.Position = UDim2.new(0, primary_width + 10, 0, 0)

	primary_button.TextSize = compact and 13 or 14
	secondary_button.TextSize = compact and 13 or 14
end

local function apply_responsive_layout()
	local viewport_size = root.AbsoluteSize
	local compact = viewport_size.X > viewport_size.Y and (viewport_size.X <= 760 or viewport_size.Y <= 430)
	local shell_inset = compact and 6 or 10
	local column_gap = compact and 6 or 10
	local sidebar_width = compact and math.clamp(math.floor(viewport_size.X * 0.29), 164, 188) or 232
	local sidebar_inset = compact and 10 or 14
	local workspace_inset = compact and 12 or 16

	shell_padding.PaddingTop = UDim.new(0, shell_inset)
	shell_padding.PaddingRight = UDim.new(0, shell_inset)
	shell_padding.PaddingBottom = UDim.new(0, shell_inset)
	shell_padding.PaddingLeft = UDim.new(0, shell_inset)
	body_layout.Padding = UDim.new(0, column_gap)

	sidebar.Size = UDim2.new(0, sidebar_width, 1, 0)
	workspace.Size = UDim2.new(1, -(sidebar_width + column_gap), 1, 0)

	sidebar_padding.PaddingTop = UDim.new(0, sidebar_inset)
	sidebar_padding.PaddingRight = UDim.new(0, sidebar_inset)
	sidebar_padding.PaddingBottom = UDim.new(0, sidebar_inset)
	sidebar_padding.PaddingLeft = UDim.new(0, sidebar_inset)

	workspace_padding.PaddingTop = UDim.new(0, compact and 12 or 14)
	workspace_padding.PaddingRight = UDim.new(0, workspace_inset)
	workspace_padding.PaddingBottom = UDim.new(0, workspace_inset)
	workspace_padding.PaddingLeft = UDim.new(0, workspace_inset)

	result_box_padding.PaddingTop = UDim.new(0, compact and 8 or 10)
	result_box_padding.PaddingRight = UDim.new(0, compact and 10 or 12)
	result_box_padding.PaddingBottom = UDim.new(0, compact and 10 or 12)
	result_box_padding.PaddingLeft = UDim.new(0, compact and 10 or 12)

	sidebar_title_label.TextSize = compact and 16 or 20
	sidebar_subtitle_label.TextSize = compact and 9 or 11
	workspace_title.TextSize = compact and 18 or 22
	workspace_subtitle.TextSize = compact and 11 or 12
	result_meta_label.TextSize = compact and 10 or 11
	result_box.TextSize = compact and 13 or 14
	status_label.TextSize = compact and 10 or 11

	update_row_button_density(mode_rows, compact)
	update_row_button_density(algorithm_rows, compact)
	update_row_button_density(digest_rows, compact)
	update_row_button_density(backend_rows, compact)

	update_action_button_density(hash_generate_button, hash_clear_button, compact)
	update_action_button_density(hmac_generate_button, hmac_clear_button, compact)
	update_action_button_density(kmac_generate_button, kmac_clear_button, compact)
	update_action_button_density(pbkdf2_generate_button, pbkdf2_clear_button, compact)
	update_action_button_density(sco_snak_generate_button, sco_snak_clear_button, compact)
	update_action_button_density(sco_reg_generate_button, sco_reg_clear_button, compact)
end

local function refresh_hash_workspace_layout()
	local supports_output_length = current_mode == "hash" and hash_algorithm_supports_output_length(current_algorithm)
	local supports_cshake = current_mode == "hash" and is_cshake_algorithm(current_algorithm)
	local current_y = 126

	hash_output_length_field.Visible = supports_output_length
	hash_function_name_field.Visible = supports_cshake
	hash_customization_field.Visible = supports_cshake

	if supports_output_length then
		hash_output_length_field.Position = UDim2.new(0, 0, 0, current_y)
		current_y += 66
	end

	if supports_cshake then
		hash_function_name_field.Position = UDim2.new(0, 0, 0, current_y)
		current_y += 66
		hash_customization_field.Position = UDim2.new(0, 0, 0, current_y)
		current_y += 66
	end

	hash_action_row.Position = UDim2.new(0, 0, 0, current_y)
	hash_workspace.Size = UDim2.new(1, 0, 0, current_y + 36)
end

local function get_current_mode_config()
	return mode_configs[current_mode] or mode_configs.hash
end

local function get_workspace_title()
	return get_current_mode_config().title
end

local function get_workspace_subtitle()
	return get_current_mode_config().subtitle
end

local function get_output_title()
	return get_current_mode_config().output_title
end

local function get_result_meta()
	return get_current_mode_config().get_result_meta()
end

local function update_result_meta()
	result_meta_label.Text = get_result_meta()
end

local function set_status(text, color)
	current_status_text = text
	current_status_color = color
	status_label.Text = text
	status_label.TextColor3 = color
	status_dot.BackgroundColor3 = color
end

local function set_result(text, color, stored_value)
	result_box.Text = text or ""
	result_box.TextColor3 = color
	current_result_value = stored_value == nil and (text or "") or stored_value
	update_result_meta()
end

local function clear_output(status_text, status_color)
	set_result(RESULT_PLACEHOLDER, palette.subtle, "")
	set_status(status_text or "Ready", status_color or palette.success)
end

local function show_error(result_text, status_text)
	set_result(result_text, palette.danger, "")
	set_status(status_text, palette.danger)
end

local function show_success(result_text, status_text)
	set_result(result_text, palette.result)
	set_status(status_text, palette.success)
end

local function format_sco_snak_result(result)
	local lines = {
		"Serial number:  " .. result.serial_number,
		"Activation key: " .. result.activation_key,
	}

	if result.license_data then
		lines[#lines + 1] = "License data:   " .. result.license_data
	end

	return table.concat(lines, "\n")
end

local function format_sco_reg_result(serial_number, host_id, registration_key)
	return table.concat({
		"Serial number:     " .. serial_number,
		"Host ID:           " .. host_id,
		"Registration key:  " .. registration_key,
	}, "\n")
end

local function run_hash_mode()
	local input_text = hash_input_box.Text or ""
	if input_text == "" then
		show_error("Please enter some text.", "Input required")
		return
	end

	if hash_algorithm_supports_output_length(current_algorithm) then
		local output_length = tonumber(hash_output_length_box.Text or "")
		if not output_length or output_length ~= math.floor(output_length) or output_length <= 0 then
			show_error("Output bytes must be a positive integer.", "Length required")
			return
		end
	end

	local hash_fn = get_hash_function()
	local ok, hash_value = pcall(hash_fn, input_text)
	if not ok then
		show_error("Hash failed: " .. tostring(hash_value), "Hash error")
		return
	end

	show_success(hash_value, "Hash generated")
end

local function run_hmac_mode()
	local key_text = hmac_key_box.Text or ""
	local message_text = hmac_message_box.Text or ""
	if key_text == "" then
		show_error("Please enter an HMAC key.", "Key required")
		return
	end

	local digest_module = hmac_digest_modules[current_hmac_digest]
	if not digest_module then
		show_error("HMAC digest selection is invalid.", "Digest error")
		return
	end

	local ok, mac_value = pcall(function()
		return hmac_module.hmac_hex(key_text, message_text, digest_module)
	end)
	if not ok then
		show_error("HMAC failed: " .. tostring(mac_value), "HMAC error")
		return
	end

	show_success(mac_value, "MAC ready")
end

local function run_kmac_mode()
	local key_text = kmac_key_box.Text or ""
	local message_text = kmac_message_box.Text or ""
	local customization_text = kmac_customization_box.Text or ""
	local output_length = tonumber(kmac_output_length_box.Text or "")

	if key_text == "" then
		show_error("Please enter a KMAC key.", "Key required")
		return
	end

	if not output_length or output_length ~= math.floor(output_length) or output_length <= 0 then
		show_error("KMAC output bytes must be a positive integer.", "Length required")
		return
	end

	local kmac_fn = current_mode == "kmac256" and sha3_module.kmac256 or sha3_module.kmac128
	local ok, mac_value = pcall(function()
		return kmac_fn(key_text, message_text, output_length, customization_text)
	end)
	if not ok then
		show_error("KMAC failed: " .. tostring(mac_value), "KMAC error")
		return
	end

	show_success(mac_value, "KMAC ready")
end

local function run_pbkdf2_mode()
	local password = pbkdf2_password_box.Text or ""
	local salt = pbkdf2_salt_box.Text or ""
	local iterations_value = tonumber(pbkdf2_iterations_box.Text or "")
	local length_value = tonumber(pbkdf2_length_box.Text or "")

	if not iterations_value or iterations_value ~= math.floor(iterations_value) or iterations_value <= 0 then
		show_error("PBKDF2 iterations must be a positive integer.", "Iterations required")
		return
	end

	if not length_value or length_value ~= math.floor(length_value) or length_value <= 0 then
		show_error("Derived key length must be a positive integer.", "Length required")
		return
	end

	local ok, derived_key = pcall(function()
		return pbkdf2_module.derive(password, salt, iterations_value, length_value, current_pbkdf2_digest)
	end)
	if not ok then
		show_error("PBKDF2 failed: " .. tostring(derived_key), "PBKDF2 error")
		return
	end

	show_success(derived_key, "Derived key ready")
end

local function run_sco_snak_mode()
	local product_id = tonumber(sco_product_id_box.Text or "")
	local major = tonumber(sco_major_box.Text or "")
	local minor = tonumber(sco_minor_box.Text or "")
	local license_data = sco_license_box.Text or ""
	local ok, result = pcall(function()
		return sco_keygen_module.generate_snak(
			product_id,
			major,
			minor,
			license_data ~= "" and license_data or nil
		)
	end)
	if not ok then
		show_error("SCO SNAK failed: " .. tostring(result), "SCO SNAK error")
		return
	end

	show_success(format_sco_snak_result(result), "SCO serial bundle ready")
end

local function run_sco_reg_mode()
	local reglock = sco_reglock_box.Text or ""
	local ok, serial_number, host_id, registration_key = pcall(function()
		if reglock ~= "" then
			local parsed = sco_keygen_module.parse_reglock(reglock)
			return parsed.serial_number, parsed.host_id, sco_keygen_module.generate_registration_key(parsed.serial_number, parsed.host_id)
		end

		local serial_value = sco_reg_serial_box.Text or ""
		local host_value = sco_host_id_box.Text or ""
		return serial_value, host_value, sco_keygen_module.generate_registration_key(serial_value, host_value)
	end)
	if not ok then
		show_error("SCO registration failed: " .. tostring(serial_number), "SCO registration error")
		return
	end

	show_success(format_sco_reg_result(serial_number, host_id, registration_key), "Registration key ready")
end

mode_configs = {
	hash = {
		title = "Hash",
		subtitle = "Generate a digest from any input string using the selected algorithm and backend.",
		output_title = "Result",
		ready_text = "Hash mode ready",
		summary_mode = "Hash",
		workspace = hash_workspace,
		show_algorithm_section = true,
		show_backend_section = true,
		show_digest_section = false,
		get_result_meta = function()
			local base = get_algorithm_label(current_algorithm) .. "  |  " .. get_backend_label(current_backend_mode) .. " backend"
			if hash_algorithm_supports_output_length(current_algorithm) then
				base = base .. "  |  " .. tostring(get_hash_output_length_value()) .. " output bytes"
			end
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return get_algorithm_label(current_algorithm)
		end,
		get_summary_engine = function()
			return get_backend_label(current_backend_mode)
		end,
		apply_defaults = function()
			if hash_algorithm_supports_output_length(current_algorithm) and hash_output_length_box.Text == "" then
				hash_output_length_box.Text = get_default_hash_output_length(current_algorithm)
			end
		end,
		clear_fields = function()
			hash_input_box.Text = ""
			hash_output_length_box.Text = get_default_hash_output_length(current_algorithm)
			hash_function_name_box.Text = ""
			hash_customization_box.Text = ""
		end,
		run = run_hash_mode,
	},
	hmac = {
		title = "HMAC",
		subtitle = "Generate a keyed message authentication code from a secret key and message using the selected digest.",
		output_title = "MAC",
		ready_text = "HMAC ready",
		summary_mode = "HMAC",
		workspace = hmac_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = true,
		allowed_digests = digest_order,
		get_result_meta = function()
			local base = "HMAC-" .. get_digest_label(current_hmac_digest)
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return get_digest_label(current_hmac_digest)
		end,
		get_summary_engine = function()
			return "Custom HMAC"
		end,
		apply_defaults = function()
		end,
		clear_fields = function()
			hmac_key_box.Text = ""
			hmac_message_box.Text = ""
		end,
		run = run_hmac_mode,
	},
	kmac128 = {
		title = "KMAC128",
		subtitle = "Generate a keyed sponge MAC using KMAC128 with an optional customization string and configurable output length.",
		output_title = "KMAC",
		ready_text = "KMAC128 ready",
		summary_mode = "KMAC128",
		workspace = kmac_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = false,
		get_result_meta = function()
			local base = "KMAC128  |  " .. tostring(tonumber(kmac_output_length_box.Text or "") or 32) .. " output bytes"
			if kmac_customization_box.Text ~= "" then
				base = base .. "  |  customized"
			end
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return "Keyed sponge MAC"
		end,
		get_summary_engine = function()
			return "cSHAKE128"
		end,
		apply_defaults = function()
			if kmac_output_length_box.Text == "" then
				kmac_output_length_box.Text = get_default_kmac_output_length("kmac128")
			end
		end,
		clear_fields = function()
			kmac_key_box.Text = ""
			kmac_message_box.Text = ""
			kmac_customization_box.Text = ""
			kmac_output_length_box.Text = get_default_kmac_output_length("kmac128")
		end,
		run = run_kmac_mode,
	},
	kmac256 = {
		title = "KMAC256",
		subtitle = "Generate a keyed sponge MAC using KMAC256 with an optional customization string and configurable output length.",
		output_title = "KMAC",
		ready_text = "KMAC256 ready",
		summary_mode = "KMAC256",
		workspace = kmac_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = false,
		get_result_meta = function()
			local base = "KMAC256  |  " .. tostring(tonumber(kmac_output_length_box.Text or "") or 64) .. " output bytes"
			if kmac_customization_box.Text ~= "" then
				base = base .. "  |  customized"
			end
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return "Keyed sponge MAC"
		end,
		get_summary_engine = function()
			return "cSHAKE256"
		end,
		apply_defaults = function()
			if kmac_output_length_box.Text == "" then
				kmac_output_length_box.Text = get_default_kmac_output_length("kmac256")
			end
		end,
		clear_fields = function()
			kmac_key_box.Text = ""
			kmac_message_box.Text = ""
			kmac_customization_box.Text = ""
			kmac_output_length_box.Text = get_default_kmac_output_length("kmac256")
		end,
		run = run_kmac_mode,
	},
	pbkdf2 = {
		title = "PBKDF2",
		subtitle = "Derive a key from a password, salt, and iteration count using HMAC-based PBKDF2.",
		output_title = "Derived key",
		ready_text = "PBKDF2 ready",
		summary_mode = "PBKDF2",
		workspace = pbkdf2_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = true,
		allowed_digests = {"sha256", "sha512"},
		get_result_meta = function()
			local iterations_text = pbkdf2_iterations_box and pbkdf2_iterations_box.Text or "1000"
			local base = "PBKDF2-HMAC-" .. get_digest_label(current_pbkdf2_digest) .. "  |  " .. iterations_text .. " iterations"
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return get_digest_label(current_pbkdf2_digest)
		end,
		get_summary_engine = function()
			return "Custom KDF"
		end,
		apply_defaults = function()
			if pbkdf2_iterations_box.Text == "" then
				pbkdf2_iterations_box.Text = "1000"
			end
			if pbkdf2_length_box.Text == "" then
				pbkdf2_length_box.Text = get_default_pbkdf2_length()
			end
		end,
		clear_fields = function()
			pbkdf2_password_box.Text = ""
			pbkdf2_salt_box.Text = ""
			pbkdf2_iterations_box.Text = "1000"
			pbkdf2_length_box.Text = get_default_pbkdf2_length()
		end,
		run = run_pbkdf2_mode,
	},
	sco_snak = {
		title = "SCO SNAK",
		subtitle = "Generate SCO serial numbers, activation keys, and optional license checksum fields.",
		output_title = "Serial bundle",
		ready_text = "SCO SNAK ready",
		summary_mode = "SCO SNAK",
		workspace = sco_snak_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = false,
		get_result_meta = function()
			local base = "SCO SNAK  |  " .. get_sco_version_summary()
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return get_sco_version_summary()
		end,
		get_summary_engine = function()
			return "MD5 port"
		end,
		apply_defaults = function()
			if sco_product_id_box.Text == "" then
				sco_product_id_box.Text = "203"
			end
			if sco_major_box.Text == "" then
				sco_major_box.Text = "71"
			end
			if sco_minor_box.Text == "" then
				sco_minor_box.Text = "4"
			end
		end,
		clear_fields = function()
			sco_product_id_box.Text = "203"
			sco_major_box.Text = "71"
			sco_minor_box.Text = "4"
			sco_license_box.Text = ""
		end,
		run = run_sco_snak_mode,
	},
	sco_reg = {
		title = "SCO Registration",
		subtitle = "Generate a SCO registration key from a serial number and host ID or from a registration lock.",
		output_title = "Registration key",
		ready_text = "SCO registration ready",
		summary_mode = "SCO Reg",
		workspace = sco_reg_workspace,
		show_algorithm_section = false,
		show_backend_section = false,
		show_digest_section = false,
		get_result_meta = function()
			local source_label = get_text_value(sco_reglock_box, "") ~= "" and "reglock input" or "serial + host ID"
			local base = "SCO registration  |  " .. source_label
			if current_result_value ~= "" then
				return base .. "  |  " .. tostring(#current_result_value) .. " chars"
			end
			return base
		end,
		get_summary_target = function()
			return get_text_value(sco_reglock_box, "") ~= "" and "Registration lock" or "Serial + host ID"
		end,
		get_summary_engine = function()
			return "MD5 port"
		end,
		apply_defaults = function()
		end,
		clear_fields = function()
			sco_reg_serial_box.Text = ""
			sco_host_id_box.Text = ""
			sco_reglock_box.Text = ""
		end,
		run = run_sco_reg_mode,
	},
}

local function refresh_summary()
	local config = get_current_mode_config()
	summary_mode_value.Text = config.summary_mode
	summary_target_value.Text = config.get_summary_target()
	summary_engine_value.Text = config.get_summary_engine()
end

local function refresh_header()
	workspace_title.Text = get_workspace_title()
	workspace_subtitle.Text = get_workspace_subtitle()
	result_title.Text = get_output_title()
	update_result_meta()
end

local function refresh_selectors()
	for mode_key, row in pairs(mode_rows) do
		style_row(row, mode_key == current_mode, true)
	end

	for algorithm_key, row in pairs(algorithm_rows) do
		style_row(row, algorithm_key == current_algorithm, true)
	end

	local current_digest_key = get_current_digest_key()
	for digest_key, row in pairs(digest_rows) do
		style_row(row, digest_key == current_digest_key, true)
	end

	for backend_key, row in pairs(backend_rows) do
		style_row(row, backend_key == current_backend_mode, true)
	end
end

local function refresh_visibility()
	local workspace_visibility = {}
	for mode_key, config in pairs(mode_configs) do
		if workspace_visibility[config.workspace] == nil then
			workspace_visibility[config.workspace] = false
		end
		if mode_key == current_mode then
			workspace_visibility[config.workspace] = true
		end
	end

	for workspace_instance, is_visible in pairs(workspace_visibility) do
		workspace_instance.Visible = is_visible
	end

	local config = get_current_mode_config()
	local native_supported = is_native_backend_supported(current_algorithm)
	sidebar_algorithm_section.Visible = config.show_algorithm_section
	sidebar_backend_section.Visible = config.show_backend_section
	sidebar_digest_section.Visible = config.show_digest_section
	refresh_hash_workspace_layout()
	for digest_key, row in pairs(digest_rows) do
		row.Visible = config.show_digest_section and mode_allows_digest(config, digest_key)
	end
	native_row.Visible = native_supported
	backend_note_label.Visible = native_supported
end

local function sync_shell()
	apply_responsive_layout()
	refresh_header()
	refresh_summary()
	refresh_selectors()
	refresh_visibility()
	update_result_meta()
end

local function apply_mode(mode_key)
	local config = mode_configs[mode_key]
	if not config then
		return
	end

	local previous_mode = current_mode
	current_mode = mode_key
	if mode_key == "kmac128" or mode_key == "kmac256" then
		local previous_default = get_default_kmac_output_length(previous_mode)
		local next_default = get_default_kmac_output_length(mode_key)
		if kmac_output_length_box.Text == "" or kmac_output_length_box.Text == previous_default then
			kmac_output_length_box.Text = next_default
		end
	end
	config.apply_defaults()
	clear_output(config.ready_text, palette.success)
	sync_shell()
end

local function apply_algorithm(algorithm_key)
	if not hash_suite[algorithm_key] then
		return
	end

	local previous_default = get_default_hash_output_length(current_algorithm)
	current_algorithm = algorithm_key
	local next_default = get_default_hash_output_length(current_algorithm)
	if next_default ~= "" then
		if hash_output_length_box.Text == "" or hash_output_length_box.Text == previous_default then
			hash_output_length_box.Text = next_default
		end
	elseif hash_output_length_box.Text == previous_default then
		hash_output_length_box.Text = ""
	end
	if current_backend_mode == "native" and not is_native_backend_supported(current_algorithm) then
		current_backend_mode = "custom"
	end
	clear_output("Algorithm selected", palette.success)
	sync_shell()
end

local function apply_backend_mode(backend_key)
	if backend_key ~= "custom" and backend_key ~= "native" then
		return
	end
	if backend_key == "native" and not is_native_backend_supported(current_algorithm) then
		current_backend_mode = "custom"
		clear_output("Native backend unavailable", palette.danger)
		sync_shell()
		return
	end

	current_backend_mode = backend_key
	clear_output("Backend selected", palette.success)
	sync_shell()
end

local function apply_pbkdf2_digest(digest_key)
	if digest_key ~= "sha256" and digest_key ~= "sha512" then
		return
	end

	local previous_default = get_default_pbkdf2_length()
	current_pbkdf2_digest = digest_key
	local next_default = get_default_pbkdf2_length()
	if pbkdf2_length_box.Text == "" or pbkdf2_length_box.Text == previous_default then
		pbkdf2_length_box.Text = next_default
	end
	clear_output("Digest selected", palette.success)
	sync_shell()
end

local function apply_hmac_digest(digest_key)
	if hmac_digest_modules[digest_key] == nil then
		return
	end

	current_hmac_digest = digest_key
	clear_output("Digest selected", palette.success)
	sync_shell()
end

local function apply_digest(digest_key)
	if current_mode == "hmac" then
		apply_hmac_digest(digest_key)
	elseif current_mode == "pbkdf2" then
		apply_pbkdf2_digest(digest_key)
	end
end

local function generate_hash()
	get_current_mode_config().run()
end

local function clear_fields()
	get_current_mode_config().clear_fields()
	clear_output("Ready", palette.success)
	sync_shell()
end

local function bind_click_map(rows, callback)
	for key, row in pairs(rows) do
		row.MouseButton1Click:Connect(function()
			callback(key)
		end)
	end
end

local function bind_submit_on_enter(text_box, mode_key)
	text_box.FocusLost:Connect(function(enter_pressed)
		if enter_pressed and current_mode == mode_key then
			generate_hash()
		end
	end)
end

bind_click_map(mode_rows, apply_mode)
bind_click_map(algorithm_rows, apply_algorithm)
bind_click_map(digest_rows, apply_digest)
bind_click_map(backend_rows, apply_backend_mode)

for _, button in ipairs({
	hash_generate_button,
	hmac_generate_button,
	kmac_generate_button,
	pbkdf2_generate_button,
	sco_snak_generate_button,
	sco_reg_generate_button,
}) do
	button.MouseButton1Click:Connect(generate_hash)
end

for _, button in ipairs({
	hash_clear_button,
	hmac_clear_button,
	kmac_clear_button,
	pbkdf2_clear_button,
	sco_snak_clear_button,
	sco_reg_clear_button,
}) do
	button.MouseButton1Click:Connect(clear_fields)
end

bind_submit_on_enter(hash_input_box, "hash")
bind_submit_on_enter(hash_output_length_box, "hash")
bind_submit_on_enter(hash_function_name_box, "hash")
bind_submit_on_enter(hash_customization_box, "hash")
bind_submit_on_enter(hmac_key_box, "hmac")
bind_submit_on_enter(hmac_message_box, "hmac")
bind_submit_on_enter(kmac_key_box, "kmac128")
bind_submit_on_enter(kmac_message_box, "kmac128")
bind_submit_on_enter(kmac_customization_box, "kmac128")
bind_submit_on_enter(kmac_output_length_box, "kmac128")
bind_submit_on_enter(kmac_key_box, "kmac256")
bind_submit_on_enter(kmac_message_box, "kmac256")
bind_submit_on_enter(kmac_customization_box, "kmac256")
bind_submit_on_enter(kmac_output_length_box, "kmac256")
bind_submit_on_enter(pbkdf2_password_box, "pbkdf2")
bind_submit_on_enter(pbkdf2_salt_box, "pbkdf2")
bind_submit_on_enter(pbkdf2_iterations_box, "pbkdf2")
bind_submit_on_enter(pbkdf2_length_box, "pbkdf2")
bind_submit_on_enter(sco_product_id_box, "sco_snak")
bind_submit_on_enter(sco_major_box, "sco_snak")
bind_submit_on_enter(sco_minor_box, "sco_snak")
bind_submit_on_enter(sco_license_box, "sco_snak")
bind_submit_on_enter(sco_reg_serial_box, "sco_reg")
bind_submit_on_enter(sco_host_id_box, "sco_reg")
bind_submit_on_enter(sco_reglock_box, "sco_reg")

root:GetPropertyChangedSignal("AbsoluteSize"):Connect(sync_shell)

sync_shell()
clear_output("Ready", palette.success)

print("Checksum Playground UI ready")
