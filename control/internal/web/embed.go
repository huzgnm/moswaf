// Package web nhung giao dien dashboard (ban build cua Vue) vao binary,
// nho vay container control plane chi can mot file duy nhat.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
