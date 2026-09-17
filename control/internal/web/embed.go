// Package web embeds the built Vue dashboard into the binary so the control plane
// container needs nothing but a single executable.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
