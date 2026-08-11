package config

import "encoding/json"

// GenerateOpenCodeConfigContent builds the OPENCODE_CONFIG_CONTENT value
// based on the permission mode. This env var is injected into the agent
// container so opencode merges it as a final local-scope config.
//
// Override mode (default): returns {"permission":"allow"} which replaces
// the host's permission object entirely — no approval dialogs inside sandbox.
//
// Merge mode: returns the host permissions as-is so they survive into the
// container. The container's own opencode.json can layer additional rules.
func GenerateOpenCodeConfigContent(perms PermissionsConfig) (string, error) {
	switch perms.Mode {
	case PermissionModeMerge:
		// Merge mode: forward the host permission rules into the container.
		if len(perms.Rules.Overrides) == 0 && perms.Rules.Default == "" {
			// No rules configured — skip injection entirely.
			return "", nil
		}
		rules := map[string]interface{}{}
		if perms.Rules.Default != "" {
			rules["default"] = perms.Rules.Default
		}
		if len(perms.Rules.Overrides) > 0 {
			rules["overrides"] = perms.Rules.Overrides
		}
		content := map[string]interface{}{
			"permission": rules,
		}
		b, err := json.Marshal(content)
		if err != nil {
			return "", err
		}
		return string(b), nil

	default: // PermissionModeOverride (empty string also defaults to override)
		// Override mode: replace host permissions with allow-all.
		// The JSON string {"permission":"allow"} is a valid opencode config
		// fragment where "allow" is shorthand for "allow everything".
		return `{"permission":"allow"}`, nil
	}
}
