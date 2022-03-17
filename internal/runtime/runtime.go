// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package runtime

import (
	"github.com/vpnhouse/tunnel/internal/settings"
	"github.com/vpnhouse/tunnel/pkg/control"
	"go.uber.org/zap"
)

type Flags struct {
	RestartRequired bool
}

type ServicesInitFunc func(runtime *TunnelRuntime) error

type TunnelRuntime struct {
	SetLogLevel control.ChangeLevelFunc
	Events      *control.EventManager
	Services    *control.ServiceMap
	Settings    *settings.Config
	Flags       Flags
	Features    FeatureSet
	starter     ServicesInitFunc
}

func (runtime *TunnelRuntime) EventChannel() chan control.Event {
	return runtime.Events.EventChannel()
}

func New(static *settings.Config, starter ServicesInitFunc) *TunnelRuntime {
	updateLogLevelFn := control.InitLogger(static.LogLevel)
	return &TunnelRuntime{
		Features:    NewFeatureSet(),
		Settings:    static,
		SetLogLevel: updateLogLevelFn,
		Events:      control.NewEventManager(),
		Services:    control.NewServiceMap(),
		starter:     starter,
	}
}

func (runtime *TunnelRuntime) ProcessEvents(event control.Event) {
	switch event.EventType {
	case control.EventSetLogLevel:
		_ = runtime.SetLogLevel(event.Info.(string))
	case control.EventRestart:
		runtime.Flags.RestartRequired = true
		if err := runtime.Restart(); err != nil {
			zap.L().Fatal("service restart failed", zap.Error(err))
		}
	default:
		zap.L().Error("ignoring unsupported event type", zap.Int("type", event.EventType))
	}
}

func (runtime *TunnelRuntime) Start() error {
	return runtime.starter(runtime)
}

func (runtime *TunnelRuntime) Stop() error {
	return runtime.Services.Shutdown()
}

func (runtime *TunnelRuntime) Restart() error {
	// Shutdown services
	err := runtime.Stop()
	if err != nil {
		return err
	}

	// Clear restart-required flag
	runtime.Flags.RestartRequired = false

	// Start new services
	err = runtime.Start()
	if err != nil {
		return err
	}

	return nil
}
