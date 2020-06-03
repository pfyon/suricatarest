-- Example lua script that can be referenced by a suricata rule in testing
function init(args)
	local needs = {}
	needs["packet"] = tostring(true)
	return needs
end

function match(args)
	-- return 0 -- Never matches
	return 1 -- Always matches
end

return 0
