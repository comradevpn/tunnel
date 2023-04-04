package manager

import (
	"fmt"
	"sync"
	"time"

	"github.com/vpnhouse/tunnel/internal/eventlog"
	"github.com/vpnhouse/tunnel/internal/runtime"
	"github.com/vpnhouse/tunnel/internal/types"
	"github.com/vpnhouse/tunnel/pkg/human"
	"github.com/vpnhouse/tunnel/proto"
	"go.uber.org/zap"
)

const (
	DefaultSentEventInterval = time.Minute
)

type trafficState struct {
	UpstreamBytesChange   int64
	DownstreamBytesChange int64
}

func (s *trafficState) Reset() {
	s.UpstreamBytesChange = 0
	s.DownstreamBytesChange = 0
}

type peerTrafficUpdateEventSender struct {
	eventLog           eventlog.EventManager
	maxUpstreamBytes   int64
	maxDownstreamBytes int64
	sendInterval       time.Duration
	stop               chan struct{}
	done               chan struct{}

	lock  sync.Mutex
	state trafficState
	// All peers (prev)
	peers map[string]*types.PeerInfo
	// peers candidates for sending
	updatedPeers map[string]*types.PeerInfo
}

func NewPeerTrafficUpdateEventSender(runtime *runtime.TunnelRuntime, eventLog eventlog.EventManager, peers []*types.PeerInfo) *peerTrafficUpdateEventSender {
	maxUpstreamBytes := int64(0)
	maxDownstreamBytes := int64(0)
	sendInterval := DefaultSentEventInterval
	if runtime.Settings != nil && runtime.Settings.PeerStatistics != nil {
		sendInterval = runtime.Settings.PeerStatistics.TrafficChangeSendEventInterval.Value()
		maxUpstreamBytes = runtime.Settings.PeerStatistics.MaxUpstreamTrafficChange.Value()
		maxDownstreamBytes = runtime.Settings.PeerStatistics.MaxDownstreamTrafficChange.Value()
	}

	peersMap := make(map[string]*types.PeerInfo, len(peers))
	for _, peer := range peers {
		if peer.WireguardPublicKey == nil {
			continue
		}
		peersMap[*peer.WireguardPublicKey] = peer
	}

	sender := &peerTrafficUpdateEventSender{
		maxUpstreamBytes:   maxUpstreamBytes,
		maxDownstreamBytes: maxDownstreamBytes,
		sendInterval:       sendInterval,
		eventLog:           eventLog,
		peers:              peersMap,
		updatedPeers:       make(map[string]*types.PeerInfo, len(peers)),
	}

	go sender.run()

	return sender
}

func (s *peerTrafficUpdateEventSender) Add(peer *types.PeerInfo) {
	if peer.WireguardPublicKey == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.peers[*peer.WireguardPublicKey] = peer
}

func (s *peerTrafficUpdateEventSender) Remove(peer *types.PeerInfo) {
	if peer.WireguardPublicKey == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := s.peers[*peer.WireguardPublicKey]; ok {
		delete(s.peers, *peer.WireguardPublicKey)
	}
}

func (s *peerTrafficUpdateEventSender) Send(peers []*types.PeerInfo) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, peer := range peers {
		oldPeer, ok := s.peers[*peer.WireguardPublicKey]
		if !ok {
			// We should never be here but for the sake of simplitity
			// assume the peer gone and simply do nothing
			continue
		}
		if peer.Upstream != nil && oldPeer.Upstream != nil {
			s.state.UpstreamBytesChange += *peer.Upstream - *oldPeer.Upstream
		}
		if peer.Downstream != nil && oldPeer.Downstream != nil {
			s.state.DownstreamBytesChange += *peer.Downstream - *oldPeer.Downstream
		}
		s.updatedPeers[*peer.WireguardPublicKey] = peer
		s.peers[*peer.WireguardPublicKey] = peer
	}

	// Check upstream or downstream exceeds the limits
	if s.maxUpstreamBytes > 0 && s.state.UpstreamBytesChange > s.maxUpstreamBytes {
		s.sendUpdates()
	} else if s.maxDownstreamBytes > 0 && s.state.DownstreamBytesChange > s.maxDownstreamBytes {
		s.sendUpdates()
	}
}

func (s *peerTrafficUpdateEventSender) sendUpdates() {
	if len(s.updatedPeers) == 0 {
		return
	}
	for _, peer := range s.updatedPeers {
		err := s.eventLog.Push(eventlog.PeerTraffic, peer.IntoProto())
		if err != nil {
			zap.L().Error("failed to push event", zap.Error(err), zap.Uint32("type", uint32(proto.EventType_PeerTraffic)))
		}
	}
	zap.L().Info(
		"send peer traffic updates",
		zap.Int("peers", len(s.updatedPeers)),
		zap.String("upstream", human.FormatSizeToHuman(uint64(s.state.UpstreamBytesChange))),
		zap.String("downstream", human.FormatSizeToHuman(uint64(s.state.DownstreamBytesChange))),
	)
	s.updatedPeers = make(map[string]*types.PeerInfo, len(s.updatedPeers))
	s.state.Reset()
}

func (s *peerTrafficUpdateEventSender) run() {
	sendPeerTicker := time.NewTicker(s.sendInterval)
	zap.L().Debug("Start sending peer traffic updates", zap.String("interval", fmt.Sprint(s.sendInterval)))

	defer func() {
		sendPeerTicker.Stop()
		close(s.done)
		zap.L().Debug("Stop sending peer traffic updates")
	}()

	for {
		select {
		case <-s.stop:
			zap.L().Info("Shutting down sending peer traffic updates")
			return
		case <-sendPeerTicker.C:
			s.lock.Lock()
			s.sendUpdates()
			s.lock.Unlock()
		}
	}
}

func (s *peerTrafficUpdateEventSender) Stop() {
	close(s.stop)
	<-s.done
}
