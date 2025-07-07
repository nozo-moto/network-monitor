//go:build !linux
// +build !linux

package collector

import (
	"github.com/cilium/ebpf"
)

// Stub implementations for non-Linux platforms

type netmonSpecs struct{}
type netmonPrograms struct{}
type netmonMaps struct{}

func loadNetmon() (*ebpf.CollectionSpec, error) {
	return nil, nil
}

func loadNetmonObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return nil
}