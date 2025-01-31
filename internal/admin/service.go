package admin

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"

	"github.com/vpnhouse/tunnel/internal/iprose"
	"github.com/vpnhouse/tunnel/internal/manager"
	"github.com/vpnhouse/tunnel/internal/storage"
	"github.com/vpnhouse/tunnel/internal/types"
)

type Service struct {
	// Manager to control over WG sessions stuff
	mgr *manager.Manager
	// Manager to control over IPRose sessions stuff
	ipr *iprose.Instance

	storage      *storage.Storage
	actionsCache *lru.Cache[string, *types.ActionRule]
}

func New(mgr *manager.Manager, ipr *iprose.Instance, storage *storage.Storage) *Service {
	actionsCache, err := lru.New[string, *types.ActionRule](1024)
	if err != nil {
		zap.L().Panic("failed to create lru cache for actions")
	}

	s := &Service{
		mgr:          mgr,
		ipr:          ipr,
		storage:      storage,
		actionsCache: actionsCache,
	}

	go s.run()

	return s
}

func (s *Service) run() {
	ctx := context.Background()
	s.storage.CleanupExpiredActionRules(ctx)
	for range time.Tick(time.Hour) {
		s.storage.CleanupExpiredActionRules(ctx)
	}
}
