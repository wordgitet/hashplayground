-- SPDX-License-Identifier: MPL-2.0
-- Hash Playground Rojo export.
-- The entire UI is built in code so Rojo can sync a self-contained utility app without hand-maintained instances.

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local screen_gui = script.Parent
screen_gui.ResetOnSpawn = false
screen_gui.IgnoreGuiInset = true
screen_gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
screen_gui.DisplayOrder = 50

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
local blake2b_module = require_module("BLAKE2bModule")
local blake3_module = require_module("BLAKE3Module")
local crc_module = require_module("CRCModule")
local pbkdf2_module = require_module("PBKDF2Module")
local sco_keygen_module = require_module("SCOKeygenModule")

local hash_suite = {
	md5 = md5_module.hash or md5_module.md5,
	sha1 = sha1_module.hash or sha1_module.sha1,
	sha256 = sha256_module.hash or sha256_module.sha256,
	sha512 = sha512_module.hash or sha512_module.sha512,
	blake2b = blake2b_module.hash or blake2b_module.blake2b,
	blake3 = blake3_module.hash or blake3_module.blake3,
	crc8 = crc_module.crc8,
	crc16 = crc_module.crc16,
	crc24 = crc_module.crc24,
	crc32 = crc_module.crc32,
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
	blake2b = "BLAKE2b",
	blake3 = "BLAKE3",
	crc8 = "CRC-8",
	crc16 = "CRC-16",
	crc24 = "CRC-24",
	crc32 = "CRC-32",
}

local algorithm_order = {"md5", "sha1", "sha256", "sha512", "blake2b", "blake3", "crc8", "crc16", "crc24", "crc32"}
local backend_labels = {
	custom = "Custom",
	native = "Native",
}
local digest_labels = {
	sha256 = "SHA-256",
	sha512 = "SHA-512",
}

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
local workspace_title
local workspace_subtitle
local hash_workspace
local pbkdf2_workspace
local sco_snak_workspace
local sco_reg_workspace
local hash_input_box
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

local function bind_canvas_size(scroller, layout)
	local function update_canvas()
		scroller.CanvasSize = UDim2.new(0, 0, 0, layout.AbsoluteContentSize.Y + 4)
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
make("UIPadding", {
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
make("UIListLayout", {
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

local sidebar = make("Frame", {
	BackgroundColor3 = palette.sidebar,
	BorderSizePixel = 0,
	LayoutOrder = 1,
	Size = UDim2.new(0, 232, 1, 0),
}, body)
add_corner(sidebar, 2)
add_stroke(sidebar, palette.border, 1, 0.7)

local sidebar_inner = make("Frame", {
	BackgroundTransparency = 1,
	BorderSizePixel = 0,
	Size = UDim2.fromScale(1, 1),
}, sidebar)
make("UIPadding", {
	PaddingBottom = UDim.new(0, 14),
	PaddingLeft = UDim.new(0, 14),
	PaddingRight = UDim.new(0, 14),
	PaddingTop = UDim.new(0, 14),
}, sidebar_inner)
make("UIListLayout", {
	Padding = UDim.new(0, 10),
	SortOrder = Enum.SortOrder.LayoutOrder,
}, sidebar_inner)

local sidebar_header = make("Frame", {
	BackgroundTransparency = 1,
	LayoutOrder = 1,
	Size = UDim2.new(1, 0, 0, 62),
}, sidebar_inner)
make("TextLabel", {
	BackgroundTransparency = 1,
	Font = Enum.Font.GothamSemibold,
	Size = UDim2.new(1, 0, 0, 26),
	Text = "Checksum Playground",
	TextColor3 = palette.text,
	TextSize = 20,
	TextXAlignment = Enum.TextXAlignment.Left,
}, sidebar_header)
make("TextLabel", {
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

local mode_section = create_section_frame(sidebar_inner, 3, 168)
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
for index, mode_data in ipairs({
	{key = "hash", label = "Hash"},
	{key = "pbkdf2", label = "PBKDF2"},
	{key = "sco_snak", label = "SCO SNAK"},
	{key = "sco_reg", label = "SCO Reg"},
}) do
	local row = create_row_button(mode_rows_holder, mode_data.label, index)
	local mode_key = mode_data.key
	mode_rows[mode_key] = row
end
create_divider(sidebar_inner, 4)

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

sidebar_digest_section = create_section_frame(sidebar_inner, 6, 92)
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
for index, digest_key in ipairs({"sha256", "sha512"}) do
	local row = create_row_button(digest_rows_holder, get_digest_label(digest_key), index)
	digest_rows[digest_key] = row
end
create_divider(sidebar_inner, 7)

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
local custom_row = create_row_button(backend_rows_holder, "Custom", 1)
local native_row = create_row_button(backend_rows_holder, "Native", 2)
backend_rows.custom = custom_row
backend_rows.native = native_row
make("TextLabel", {
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
summary_mode_value = create_summary_row(summary_holder, 1, "Mode")
summary_target_value = create_summary_row(summary_holder, 2, "Target")
summary_engine_value = create_summary_row(summary_holder, 3, "Engine")

local workspace = make("Frame", {
	BackgroundColor3 = palette.panel,
	BorderSizePixel = 0,
	LayoutOrder = 2,
	Size = UDim2.new(1, -242, 1, 0),
}, body)
add_corner(workspace, 2)
add_stroke(workspace, palette.border, 1, 0.72)
make("UIPadding", {
	PaddingBottom = UDim.new(0, 16),
	PaddingLeft = UDim.new(0, 16),
	PaddingRight = UDim.new(0, 16),
	PaddingTop = UDim.new(0, 14),
}, workspace)
make("UIListLayout", {
	Padding = UDim.new(0, 12),
	SortOrder = Enum.SortOrder.LayoutOrder,
}, workspace)

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
create_divider(workspace, 2)

hash_workspace = create_section_frame(workspace, 3, 204)
local _, hash_input = create_field(hash_workspace, "Input", "Type or paste text to hash", true, 118, false)
hash_input_box = hash_input
hash_input.Position = UDim2.new(0, 0, 0, 0)
local hash_action_row = make("Frame", {
	BackgroundTransparency = 1,
	Position = UDim2.new(0, 0, 1, -36),
	Size = UDim2.new(1, 0, 0, 36),
}, hash_workspace)
local hash_generate_button = create_action_button(hash_action_row, "Generate Hash", true, UDim2.new(0, 164, 1, 0))
local hash_clear_button = create_action_button(hash_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
hash_clear_button.Position = UDim2.new(0, 174, 0, 0)

pbkdf2_workspace = create_section_frame(workspace, 4, 238)
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
local pbkdf2_generate_button = create_action_button(pbkdf2_action_row, "Derive Key", true, UDim2.new(0, 164, 1, 0))
local pbkdf2_clear_button = create_action_button(pbkdf2_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
pbkdf2_clear_button.Position = UDim2.new(0, 174, 0, 0)

sco_snak_workspace = create_section_frame(workspace, 5, 238)
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
local sco_snak_generate_button = create_action_button(sco_snak_action_row, "Generate SNAK", true, UDim2.new(0, 164, 1, 0))
local sco_snak_clear_button = create_action_button(sco_snak_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
sco_snak_clear_button.Position = UDim2.new(0, 174, 0, 0)

sco_reg_workspace = create_section_frame(workspace, 6, 256)
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
local sco_reg_generate_button = create_action_button(sco_reg_action_row, "Generate Key", true, UDim2.new(0, 164, 1, 0))
local sco_reg_clear_button = create_action_button(sco_reg_action_row, "Clear", false, UDim2.new(0, 110, 1, 0))
sco_reg_clear_button.Position = UDim2.new(0, 174, 0, 0)

create_divider(workspace, 7)

local result_panel = create_section_frame(workspace, 8, 210)
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
make("UIPadding", {
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

local function get_workspace_title()
	if current_mode == "pbkdf2" then
		return "PBKDF2"
	elseif current_mode == "sco_snak" then
		return "SCO SNAK"
	elseif current_mode == "sco_reg" then
		return "SCO Registration"
	end
	return "Hash"
end

local function get_workspace_subtitle()
	if current_mode == "pbkdf2" then
		return "Derive a key from a password, salt, and iteration count using HMAC-based PBKDF2."
	elseif current_mode == "sco_snak" then
		return "Generate SCO serial numbers, activation keys, and optional license checksum fields."
	elseif current_mode == "sco_reg" then
		return "Generate a SCO registration key from a serial number and host ID or from a registration lock."
	end
	return "Generate a digest from any input string using the selected algorithm and backend."
end

local function get_output_title()
	if current_mode == "pbkdf2" then
		return "Derived key"
	elseif current_mode == "sco_snak" then
		return "Serial bundle"
	elseif current_mode == "sco_reg" then
		return "Registration key"
	end
	return "Result"
end

local function get_result_meta()
	if current_mode == "pbkdf2" then
		local iterations_text = pbkdf2_iterations_box and pbkdf2_iterations_box.Text or "1000"
		local base = "PBKDF2-HMAC-" .. get_digest_label(current_pbkdf2_digest) .. "  |  " .. iterations_text .. " iterations"
		if current_result_value ~= "" then
			return base .. "  |  " .. tostring(#current_result_value) .. " chars"
		end
		return base
	end

	if current_mode == "sco_snak" then
		local base = "SCO SNAK  |  " .. get_sco_version_summary()
		if current_result_value ~= "" then
			return base .. "  |  " .. tostring(#current_result_value) .. " chars"
		end
		return base
	end

	if current_mode == "sco_reg" then
		local source_label = get_text_value(sco_reglock_box, "") ~= "" and "reglock input" or "serial + host ID"
		local base = "SCO registration  |  " .. source_label
		if current_result_value ~= "" then
			return base .. "  |  " .. tostring(#current_result_value) .. " chars"
		end
		return base
	end

	local base = get_algorithm_label(current_algorithm) .. "  |  " .. get_backend_label(current_backend_mode) .. " backend"
	if current_result_value ~= "" then
		return base .. "  |  " .. tostring(#current_result_value) .. " chars"
	end
	return base
end

local function set_status(text, color)
	current_status_text = text
	current_status_color = color
	status_label.Text = text
	status_label.TextColor3 = color
	status_dot.BackgroundColor3 = color
end

local function set_result(text, color)
	current_result_value = text or ""
	result_box.Text = text
	result_box.TextColor3 = color
	result_meta_label.Text = get_result_meta()
end

local function clear_output(status_text, status_color)
	set_result("The output will appear here", palette.subtle)
	current_result_value = ""
	result_meta_label.Text = get_result_meta()
	set_status(status_text or "Ready", status_color or palette.success)
end

local function refresh_summary()
	if current_mode == "pbkdf2" then
		summary_mode_value.Text = "PBKDF2"
		summary_target_value.Text = get_digest_label(current_pbkdf2_digest)
		summary_engine_value.Text = "Custom KDF"
	elseif current_mode == "sco_snak" then
		summary_mode_value.Text = "SCO SNAK"
		summary_target_value.Text = get_sco_version_summary()
		summary_engine_value.Text = "MD5 port"
	elseif current_mode == "sco_reg" then
		summary_mode_value.Text = "SCO Reg"
		summary_target_value.Text = get_text_value(sco_reglock_box, "") ~= "" and "Registration lock" or "Serial + host ID"
		summary_engine_value.Text = "MD5 port"
	else
		summary_mode_value.Text = "Hash"
		summary_target_value.Text = get_algorithm_label(current_algorithm)
		summary_engine_value.Text = get_backend_label(current_backend_mode)
	end
end

local function refresh_header()
	workspace_title.Text = get_workspace_title()
	workspace_subtitle.Text = get_workspace_subtitle()
	result_title.Text = get_output_title()
	result_meta_label.Text = get_result_meta()
end

local function refresh_selectors()
	for mode_key, row in pairs(mode_rows) do
		style_row(row, mode_key == current_mode, true)
	end

	for algorithm_key, row in pairs(algorithm_rows) do
		style_row(row, algorithm_key == current_algorithm, true)
	end

	for digest_key, row in pairs(digest_rows) do
		style_row(row, digest_key == current_pbkdf2_digest, true)
	end

	for backend_key, row in pairs(backend_rows) do
		local enabled = backend_key ~= "native" or is_native_backend_supported(current_algorithm)
		style_row(row, backend_key == current_backend_mode and enabled, enabled)
	end
end

local function refresh_visibility()
	local hash_mode = current_mode == "hash"
	local pbkdf2_mode = current_mode == "pbkdf2"
	local sco_snak_mode = current_mode == "sco_snak"
	local sco_reg_mode = current_mode == "sco_reg"
	hash_workspace.Visible = hash_mode
	pbkdf2_workspace.Visible = pbkdf2_mode
	sco_snak_workspace.Visible = sco_snak_mode
	sco_reg_workspace.Visible = sco_reg_mode
	sidebar_algorithm_section.Visible = hash_mode
	sidebar_backend_section.Visible = hash_mode
	sidebar_digest_section.Visible = pbkdf2_mode
end

local function sync_shell()
	refresh_header()
	refresh_summary()
	refresh_selectors()
	refresh_visibility()
	result_meta_label.Text = get_result_meta()
end

local function apply_mode(mode_key)
	if mode_key ~= "hash" and mode_key ~= "pbkdf2" and mode_key ~= "sco_snak" and mode_key ~= "sco_reg" then
		return
	end

	current_mode = mode_key
	local ready_text = "Hash mode ready"
	if mode_key == "pbkdf2" then
		ready_text = "PBKDF2 ready"
	elseif mode_key == "sco_snak" then
		ready_text = "SCO SNAK ready"
	elseif mode_key == "sco_reg" then
		ready_text = "SCO registration ready"
	end
	clear_output(ready_text, palette.success)
	if current_mode == "pbkdf2" then
		if pbkdf2_iterations_box.Text == "" then
			pbkdf2_iterations_box.Text = "1000"
		end
		if pbkdf2_length_box.Text == "" then
			pbkdf2_length_box.Text = current_pbkdf2_digest == "sha512" and "64" or "32"
		end
	elseif current_mode == "sco_snak" then
		if sco_product_id_box.Text == "" then
			sco_product_id_box.Text = "203"
		end
		if sco_major_box.Text == "" then
			sco_major_box.Text = "71"
		end
		if sco_minor_box.Text == "" then
			sco_minor_box.Text = "4"
		end
	end
	current_result_value = ""
	sync_shell()
end

local function apply_algorithm(algorithm_key)
	if not hash_suite[algorithm_key] then
		return
	end

	current_algorithm = algorithm_key
	if current_backend_mode == "native" and not is_native_backend_supported(current_algorithm) then
		current_backend_mode = "custom"
	end
	clear_output("Algorithm selected", palette.success)
	current_result_value = ""
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
	current_result_value = ""
	sync_shell()
end

local function apply_pbkdf2_digest(digest_key)
	if digest_key ~= "sha256" and digest_key ~= "sha512" then
		return
	end

	local previous_default = current_pbkdf2_digest == "sha512" and "64" or "32"
	current_pbkdf2_digest = digest_key
	local next_default = current_pbkdf2_digest == "sha512" and "64" or "32"
	if pbkdf2_length_box.Text == "" or pbkdf2_length_box.Text == previous_default then
		pbkdf2_length_box.Text = next_default
	end
	clear_output("Digest selected", palette.success)
	current_result_value = ""
	sync_shell()
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

local function generate_hash()
	if current_mode == "sco_snak" then
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
			set_result("SCO SNAK failed: " .. tostring(result), palette.danger)
			current_result_value = ""
			set_status("SCO SNAK error", palette.danger)
			result_meta_label.Text = get_result_meta()
			return
		end

		set_result(format_sco_snak_result(result), palette.result)
		set_status("SCO serial bundle ready", palette.success)
		return
	end

	if current_mode == "sco_reg" then
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
			set_result("SCO registration failed: " .. tostring(serial_number), palette.danger)
			current_result_value = ""
			set_status("SCO registration error", palette.danger)
			result_meta_label.Text = get_result_meta()
			return
		end

		set_result(format_sco_reg_result(serial_number, host_id, registration_key), palette.result)
		set_status("Registration key ready", palette.success)
		return
	end

	if current_mode == "pbkdf2" then
		local password = pbkdf2_password_box.Text or ""
		local salt = pbkdf2_salt_box.Text or ""
		local iterations_value = tonumber(pbkdf2_iterations_box.Text or "")
		local length_value = tonumber(pbkdf2_length_box.Text or "")

		if not iterations_value or iterations_value ~= math.floor(iterations_value) or iterations_value <= 0 then
			set_result("PBKDF2 iterations must be a positive integer.", palette.danger)
			current_result_value = ""
			set_status("Iterations required", palette.danger)
			result_meta_label.Text = get_result_meta()
			return
		end

		if not length_value or length_value ~= math.floor(length_value) or length_value <= 0 then
			set_result("Derived key length must be a positive integer.", palette.danger)
			current_result_value = ""
			set_status("Length required", palette.danger)
			result_meta_label.Text = get_result_meta()
			return
		end

		local ok, derived_key = pcall(function()
			return pbkdf2_module.derive(password, salt, iterations_value, length_value, current_pbkdf2_digest)
		end)
		if not ok then
			set_result("PBKDF2 failed: " .. tostring(derived_key), palette.danger)
			current_result_value = ""
			set_status("PBKDF2 error", palette.danger)
			result_meta_label.Text = get_result_meta()
			return
		end

		set_result(derived_key, palette.result)
		set_status("Derived key ready", palette.success)
		return
	end

	local input_text = hash_input_box.Text or ""
	if input_text == "" then
		set_result("Please enter some text.", palette.danger)
		current_result_value = ""
		set_status("Input required", palette.danger)
		result_meta_label.Text = get_result_meta()
		return
	end

	local hash_fn = get_hash_function()
	local ok, hash_value = pcall(hash_fn, input_text)
	if not ok then
		set_result("Hash failed: " .. tostring(hash_value), palette.danger)
		current_result_value = ""
		set_status("Hash error", palette.danger)
		result_meta_label.Text = get_result_meta()
		return
	end

	set_result(hash_value, palette.result)
	set_status("Hash generated", palette.success)
end

local function clear_fields()
	if current_mode == "pbkdf2" then
		pbkdf2_password_box.Text = ""
		pbkdf2_salt_box.Text = ""
		pbkdf2_iterations_box.Text = "1000"
		pbkdf2_length_box.Text = current_pbkdf2_digest == "sha512" and "64" or "32"
	elseif current_mode == "sco_snak" then
		sco_product_id_box.Text = "203"
		sco_major_box.Text = "71"
		sco_minor_box.Text = "4"
		sco_license_box.Text = ""
	elseif current_mode == "sco_reg" then
		sco_reg_serial_box.Text = ""
		sco_host_id_box.Text = ""
		sco_reglock_box.Text = ""
	else
		hash_input_box.Text = ""
	end
	clear_output("Ready", palette.success)
	sync_shell()
end

for mode_key, row in pairs(mode_rows) do
	row.MouseButton1Click:Connect(function()
		apply_mode(mode_key)
	end)
end

for algorithm_key, row in pairs(algorithm_rows) do
	row.MouseButton1Click:Connect(function()
		apply_algorithm(algorithm_key)
	end)
end

for digest_key, row in pairs(digest_rows) do
	row.MouseButton1Click:Connect(function()
		apply_pbkdf2_digest(digest_key)
	end)
end

for backend_key, row in pairs(backend_rows) do
	row.MouseButton1Click:Connect(function()
		apply_backend_mode(backend_key)
	end)
end

hash_generate_button.MouseButton1Click:Connect(generate_hash)
hash_clear_button.MouseButton1Click:Connect(clear_fields)
pbkdf2_generate_button.MouseButton1Click:Connect(generate_hash)
pbkdf2_clear_button.MouseButton1Click:Connect(clear_fields)
sco_snak_generate_button.MouseButton1Click:Connect(generate_hash)
sco_snak_clear_button.MouseButton1Click:Connect(clear_fields)
sco_reg_generate_button.MouseButton1Click:Connect(generate_hash)
sco_reg_clear_button.MouseButton1Click:Connect(clear_fields)

hash_input_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "hash" then
		generate_hash()
	end
end)

pbkdf2_password_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "pbkdf2" then
		generate_hash()
	end
end)

pbkdf2_salt_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "pbkdf2" then
		generate_hash()
	end
end)

pbkdf2_iterations_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "pbkdf2" then
		generate_hash()
	end
end)

pbkdf2_length_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "pbkdf2" then
		generate_hash()
	end
end)

sco_product_id_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_snak" then
		generate_hash()
	end
end)

sco_major_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_snak" then
		generate_hash()
	end
end)

sco_minor_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_snak" then
		generate_hash()
	end
end)

sco_license_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_snak" then
		generate_hash()
	end
end)

sco_reg_serial_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_reg" then
		generate_hash()
	end
end)

sco_host_id_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_reg" then
		generate_hash()
	end
end)

sco_reglock_box.FocusLost:Connect(function(enter_pressed)
	if enter_pressed and current_mode == "sco_reg" then
		generate_hash()
	end
end)

sync_shell()
clear_output("Ready", palette.success)

print("Checksum Playground UI ready")
