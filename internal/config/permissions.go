package config

const (
	// PermissionModeOverride replaces host permissions entirely with sandbox rules.
	PermissionModeOverride = "override"
	// PermissionModeMerge layers sandbox rules on top of host permissions.
	PermissionModeMerge = "merge"
)

// PermissionsConfig controls how the sandbox handles opencode permission rules.
type PermissionsConfig struct {
	// Mode determines how sandbox permissions interact with host permissions.
	// "override" (default): sandbox generates a complete permission block,
	//   replacing the host's permission rules entirely inside the container.
	// "merge": host permission rules survive; sandbox adds/restricts on top
	//   via deep-merge.
	Mode string `yaml:"mode,omitempty"`

	// Rules defines the permission block injected into the sandbox.
	Rules PermissionRules `yaml:"rules,omitempty"`
}

// PermissionRules defines the permission values injected into the sandbox.
type PermissionRules struct {
	// Default is the base permission action applied to all tools.
	// "allow" (default in override mode): everything permitted, no dialogs.
	// "deny": everything blocked.
	// "ask": prompt for each action.
	Default string `yaml:"default,omitempty"`

	// Overrides are per-tool permission patterns (tool → pattern → action).
	// Only effective in "override" mode to add specific restrictions on top
	// of the default. Example:
	//   bash:
	//     "rm -rf /": deny
	Overrides map[string]map[string]string `yaml:"overrides,omitempty"`
}
