//go:build !windows

package srum

import "errors"

func SnapshotLive(string) (string, error) {
	return "", errors.New("SRUM only exists on Windows; use --file to import a copied SRUDB.dat")
}
