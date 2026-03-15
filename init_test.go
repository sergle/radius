package radius

func init() {
	// For testing purposes, we load the builtin dictionary automatically.
	// This ensures that all tests have access to standard RFC 2865 attributes.
	// In production, the user must explicitly load a dictionary.
	defaultDictionary.loadFileInternal("dictionary.builtin")
}
