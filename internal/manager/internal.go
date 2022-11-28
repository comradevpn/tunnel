// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package manager

import (
	"errors"
	"time"

	"github.com/vpnhouse/tunnel/internal/types"
	"github.com/vpnhouse/tunnel/pkg/ippool"
	"github.com/vpnhouse/tunnel/pkg/xerror"
	"github.com/vpnhouse/tunnel/pkg/xtime"
	"github.com/vpnhouse/tunnel/proto"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (manager *Manager) peers() ([]types.PeerInfo, error) {
	return manager.storage.SearchPeers(nil)
}

// restore peers on startup
func (manager *Manager) restorePeers() {
	peers, err := manager.peers()
	if err != nil {
		// err has already been logged inside
		return
	}

	for _, peer := range peers {
		if peer.Expired() {
			zap.L().Debug("wiping expired peer", zap.Any("peer", peer))
			_ = manager.storage.DeletePeer(peer.ID)
			continue
		}

		if err := manager.ip4am.Set(*peer.Ipv4, peer.GetNetworkPolicy()); err != nil {
			if !errors.Is(err, ippool.ErrNotInRange) {
				continue
			}

			newIP, err := manager.ip4am.Alloc(peer.GetNetworkPolicy())
			if err != nil {
				// TODO(nikonov): remove peer OR mark it as invalid
				//  to allow further migration by hand.
				continue
			}
			peer.Ipv4 = &newIP
			if _, err := manager.storage.UpdatePeer(peer); err != nil {
				continue
			}
		}

		_ = manager.wireguard.SetPeer(peer)
		allPeersGauge.Inc()
	}
}

func (manager *Manager) unsetPeer(peer types.PeerInfo) error {
	errManager := manager.storage.DeletePeer(peer.ID)
	errWireguard := manager.wireguard.UnsetPeer(peer)
	errPool := manager.ip4am.Unset(*peer.Ipv4)

	// TODO(nikonov): report an actual traffic on remove
	allPeersGauge.Dec()
	if err := manager.eventLog.Push(uint32(proto.EventType_PeerRemove), time.Now().Unix(), peer.IntoProto()); err != nil {
		// do not return an error here because it's not related to the method itself.
		zap.L().Error("failed to push event", zap.Error(err), zap.Uint32("type", uint32(proto.EventType_PeerRemove)))
	}

	return func(errors ...error) error {
		for _, e := range errors {
			if e != nil {
				return e
			}
		}
		return nil
	}(errManager, errPool, errWireguard)
}

// setPeer mutates the given PeerInfo,
// fields: ID, IPv4
func (manager *Manager) setPeer(peer *types.PeerInfo) error {
	err := func() error {
		if peer.Expired() {
			return xerror.EInvalidArgument("peer already expired", nil)
		}

		if peer.Ipv4 == nil || peer.Ipv4.IP == nil {
			// Allocate IP, if necessary
			ipv4, err := manager.ip4am.Alloc(peer.GetNetworkPolicy())
			if err != nil {
				return err
			}

			peer.Ipv4 = &ipv4
		} else {
			// Check if IP can be used
			err := manager.ip4am.Set(*peer.Ipv4, peer.GetNetworkPolicy())
			if err != nil {
				return err
			}
		}

		// Create peer in storage
		id, err := manager.storage.CreatePeer(*peer)
		if err != nil {
			return err
		}
		peer.ID = id

		// Set peer in wireguard
		if err := manager.wireguard.SetPeer(*peer); err != nil {
			return err
		}

		return nil
	}()

	// rollback an action on error
	if err != nil {
		if peer.Ipv4 != nil {
			_ = manager.ip4am.Unset(*peer.Ipv4)
		}

		if peer.ID > 0 {
			_ = manager.storage.DeletePeer(peer.ID)
		}

		return err
	}

	allPeersGauge.Inc()
	if err := manager.eventLog.Push(uint32(proto.EventType_PeerAdd), time.Now().Unix(), peer.IntoProto()); err != nil {
		// do not return an error here because it's not related to the method itself.
		zap.L().Error("failed to push event", zap.Error(err), zap.Uint32("type", uint32(proto.EventType_PeerAdd)))
	}
	return nil
}

// updatePeer mutates given newPeer,
// fields: ID, IPv4
func (manager *Manager) updatePeer(newPeer *types.PeerInfo) error {
	if newPeer.Expired() {
		return manager.unsetPeer(*newPeer)
	}

	// Find old peer to remove it from wireguard interface
	oldPeer, err := manager.storage.GetPeer(newPeer.ID)
	if err != nil {
		return err
	}

	ipOK, dbOK, wgOK, err := func() (bool, bool, bool, error) {
		var ipOK, dbOK, wgOK bool
		// Prepare ipv4 address
		if newPeer.Ipv4 == nil {
			// IP is not set - allocate new one
			ipv4, err := manager.ip4am.Alloc(newPeer.GetNetworkPolicy())
			if err != nil {
				// TODO: Differentiate log level by error type (i.e. no space is debug message, others are errors)
				zap.L().Debug("can't allocate new IP for existing peer", zap.Error(err))

				// Something went wrong - use old IP
				newPeer.Ipv4 = oldPeer.Ipv4
			} else {
				// Hurrah, we have new IP!
				newPeer.Ipv4 = &ipv4
			}
		} else if !newPeer.Ipv4.Equal(*oldPeer.Ipv4) {
			// Try to set up new ip, if it differs from old one
			if err := manager.ip4am.Set(*newPeer.Ipv4, newPeer.GetNetworkPolicy()); err != nil {
				return ipOK, dbOK, wgOK, err
			}
		}

		// We finished IP updating
		ipOK = true

		// Update database
		now := xtime.Now()
		newPeer.Updated = &now
		id, err := manager.storage.UpdatePeer(*newPeer)
		if err != nil {
			return ipOK, dbOK, wgOK, err
		}
		// We finished database updating
		newPeer.ID = id
		dbOK = true

		// Update wireguard peer
		if *oldPeer.WireguardPublicKey != *newPeer.WireguardPublicKey {
			// Key changed - we need remove old peer and set new
			if err := manager.wireguard.UnsetPeer(oldPeer); err != nil {
				return ipOK, dbOK, wgOK, err
			}
		}

		if err := manager.wireguard.SetPeer(*newPeer); err != nil {
			zap.L().Error("failed to set new peer, trying to revert old", zap.Error(err))
			err = manager.wireguard.SetPeer(oldPeer)
			return ipOK, dbOK, wgOK, err
		}

		wgOK = true
		return ipOK, dbOK, wgOK, err
	}()

	// Reverting back
	if err != nil {
		if dbOK {
			// Try to revert peer state
			_, _ = manager.storage.UpdatePeer(oldPeer)
		}

		if ipOK && !newPeer.Ipv4.Equal(*oldPeer.Ipv4) {
			// Try to cleanup new IP
			_ = manager.ip4am.Unset(*newPeer.Ipv4)
		}

		if wgOK {
			// Try to revert wireguard peer
			_ = manager.wireguard.UnsetPeer(*newPeer)
			_ = manager.wireguard.SetPeer(oldPeer)
		}

		return err
	}

	// TODO(nikonov): report an actual traffic on update
	if err := manager.eventLog.Push(uint32(proto.EventType_PeerUpdate), time.Now().Unix(), newPeer.IntoProto()); err != nil {
		// do not return an error here because it's not related to the method itself.
		zap.L().Error("failed to push event", zap.Error(err), zap.Uint32("type", uint32(proto.EventType_PeerUpdate)))
	}
	return nil
}

func (manager *Manager) findPeerByIdentifiers(identifiers *types.PeerIdentifiers) (types.PeerInfo, error) {
	if identifiers == nil {
		return types.PeerInfo{}, xerror.EInvalidArgument("no identifiers", nil)
	}

	peerQuery := types.PeerInfo{
		PeerIdentifiers: *identifiers,
	}

	peers, err := manager.storage.SearchPeers(&peerQuery)
	if err != nil {
		return types.PeerInfo{}, err
	}

	if len(peers) == 0 {
		return types.PeerInfo{}, xerror.EEntryNotFound("peer not found", nil)
	}

	if len(peers) > 1 {
		return types.PeerInfo{}, xerror.EInvalidArgument("not enough identifiers to update peer", nil)
	}

	return peers[0], nil
}

func (manager *Manager) lock() error {
	if !manager.running.Load() {
		return xerror.EUnavailable("server is shutting down", nil)
	}
	manager.mutex.Lock()
	return nil
}

func (manager *Manager) unlock() {
	manager.mutex.Unlock()
}

func (manager *Manager) updatePeerStats() {
	if err := manager.lock(); err != nil {
		return
	}
	defer manager.unlock()

	linkStats, err := manager.wireguard.GetLinkStatistic()
	if err == nil {
		// non-nil error will be logged
		// by the common.Error inside the method.
		updatePrometheusFromLinkStats(linkStats)
	}

	// ignore error because it logged by the common.Error wrapper.
	// it is safe to call reportTrafficByPeer with nil map.
	wireguardPeers, _ := manager.wireguard.GetPeers()

	peers, err := manager.peers()
	if err != nil {
		return
	}

	results := manager.statsService.UpdatePeerStats(peers, wireguardPeers)

	// Tidy up expired and calc total peers
	for _, peer := range results.ExpiredPeers {
		err = manager.unsetPeer(*peer)
		if err != nil {
			zap.L().Error("failed to unset expired peer", zap.Error(err))
		}
	}

	// Send events along updated peer stats
	for _, peer := range results.UpdatedPeers {
		err = manager.eventLog.Push(uint32(proto.EventType_PeerTraffic), time.Now().Unix(), peer.IntoProto())
		if err != nil {
			zap.L().Error("failed to push event", zap.Error(err), zap.Uint32("type", uint32(proto.EventType_PeerTraffic)))
		}
	}

	diffUpstream := linkStats.RxBytes
	diffDownstream := linkStats.TxBytes
	if manager.statistic.LinkStat != nil {
		diffUpstream -= manager.statistic.LinkStat.RxBytes
		diffDownstream -= manager.statistic.LinkStat.TxBytes
	}

	manager.statistic = CachedStatistics{
		PeersTotal:          results.NumPeers,
		PeersWithTraffic:    results.NumPeersWithHadshakes,
		PeersActiveLastHour: results.NumPeersActiveLastHour,
		PeersActiveLastDay:  results.NumPeersActiveLastDay,
		LinkStat:            linkStats,
		Upstream:            manager.statistic.Upstream + int64(diffUpstream),
		Downstream:          manager.statistic.Downstream + int64(diffDownstream),
	}

	zap.L().Info("STATS",
		zap.Int("total", results.NumPeers),
		zap.Int("connected", results.NumPeersWithHadshakes),
		zap.Int("active_1h", results.NumPeersActiveLastHour),
		zap.Int("active_1d", results.NumPeersActiveLastDay),
		zap.Int("rx_bytes", int(linkStats.RxBytes)),
		zap.Int("rx_packets", int(linkStats.RxPackets)),
		zap.Int("tx_bytes", int(linkStats.TxBytes)),
		zap.Int("tx_packets", int(linkStats.TxPackets)))

	peersWithHandshakesGauge.Set(float64(results.NumPeersWithHadshakes))
	manager.storage.SetUpstreamMetric(manager.statistic.Upstream)
	manager.storage.SetDownstreamMetric(manager.statistic.Downstream)
}

func (manager *Manager) background() {
	// TODO (Sergey Kovalev): Move interval to settings
	expirationTicker := time.NewTicker(time.Second * 60)
	defer func() {
		expirationTicker.Stop()
		close(manager.done)
	}()

	for {
		select {
		case <-manager.stop:
			zap.L().Info("Shutting down manager background process")
			return
		case <-expirationTicker.C:
			manager.updatePeerStats()
		}
	}
}

// findWgPeerByPublicKey returns wireguard peer for matching peer public key, if any.
func findWgPeerByPublicKey(peer types.PeerInfo, wgPeers map[string]wgtypes.Peer) (wgtypes.Peer, bool) {
	// make it safe to call with empty or nil map
	if len(wgPeers) == 0 {
		return wgtypes.Peer{}, false
	}

	if peer.WireguardPublicKey == nil {
		// should this ever happen?
		// why we even have this as string *pointer*?
		zap.L().Error("got a peer without the public key",
			zap.Any("id", peer.ID),
			zap.Any("user_id", peer.UserId),
			zap.Any("install_id", peer.InstallationId))
		return wgtypes.Peer{}, false
	}

	key := *peer.WireguardPublicKey
	wgPeer, ok := wgPeers[key]
	if !ok {
		zap.L().Error("peer is presented in the manager's storage but not configured on the interface",
			zap.String("pub_key", *peer.WireguardPublicKey),
			zap.Any("id", peer.ID),
			zap.Any("user_id", peer.UserId),
			zap.Any("install_id", peer.InstallationId))
		return wgtypes.Peer{}, false
	}

	return wgPeer, true
}
