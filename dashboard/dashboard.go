// Package dashboard embeds the static dashboard so the collector ships as a
// single file. Edit index.html, app.js and style.css directly.
package dashboard

import "embed"

//go:embed index.html app.js style.css
var Files embed.FS
