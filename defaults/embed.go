package defaults

import "embed"

//go:embed starlark/*.star
var StarlarkScripts embed.FS
