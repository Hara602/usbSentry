//go:build windows

package watcher

import "usbSentry/internal/model"

type winWatcher struct{}

func newWatcher() DeviceWatcher                             { return &winWatcher{} }
func (w *winWatcher) Start() (<-chan model.USBEvent, error) { return nil, nil }
func (w *winWatcher) Stop()                                 {}
