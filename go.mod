module github.com/opencallslow/opencallslow

go 1.27.0

require (
	github.com/0xrawsec/golang-etw v1.6.2
	github.com/Velocidex/ordereddict v0.0.0-20250821063524-02dc06e46238
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	modernc.org/sqlite v1.60.1
	www.velocidex.com/golang/go-ese v0.2.0
)

require (
	github.com/0xrawsec/golang-utils v1.3.1 // indirect
	github.com/Velocidex/json v0.0.0-20220224052537-92f3c0326e5a // indirect
	github.com/Velocidex/yaml/v2 v2.2.8 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace www.velocidex.com/golang/go-ese => ./third_party/go-ese
