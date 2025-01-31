package admin

import (
	"context"
	"errors"
	"time"

	"github.com/vpnhouse/tunnel/internal/types"
	"go.uber.org/zap"
)

var ActionRulesCheckErrors = map[types.ActionRuleType]error{
	types.ActionRuleRestrict: errors.New(string(types.ActionRuleRestrict)),
}

type AddRestrictionRequest struct {
	UserId         string
	InstallationId string
	SessionId      string
	ExpiredTo      int64
}

type DeleteRestrictionRequest struct {
	UserId string
}

func (s *Service) AddRestriction(ctx context.Context, req *AddRestrictionRequest) error {
	var expires *int64
	if req.ExpiredTo > 0 {
		expires = &req.ExpiredTo
	}
	err := s.storage.AddActionRule(ctx, &types.ActionRule{
		UserId:  req.UserId,
		Expires: expires,
		Action:  types.ActionRuleRestrict,
	})
	if err != nil {
		return err
	}

	// TODO: Add handling add restriction event
	return nil
}

func (s *Service) DeleteRestriction(ctx context.Context, req *DeleteRestrictionRequest) error {
	err := s.storage.DeleteActionRules(req.UserId, types.ActionRuleRestrict)
	if err != nil {
		return err
	}
	// TODO: Add handling delete restriction event
	return nil
}

func (s *Service) CheckUserByActionRules(ctx context.Context, userId string, serverTime ...*time.Time) error {
	now := time.Now().UTC()
	if len(serverTime) == 1 {
		now = *(serverTime[0])
	}
	for actionType, actionCheckError := range ActionRulesCheckErrors {
		// Can return nil if error or no rule for this user
		key := userId + "/" + string(actionType)
		actionRule, ok := s.actionsCache.Get(key)
		if !ok {
			actionRule = s.getActionRule(ctx, userId, actionType)
			s.actionsCache.Add(key, actionRule)
		}
		if actionRule == nil {
			continue
		}

		if actionRule.IsActive(now) {
			return actionCheckError
		}
	}
	return nil
}

func (s *Service) getActionRule(ctx context.Context, userId string, actionRuleType types.ActionRuleType) *types.ActionRule {
	actionRules, err := s.storage.FindActionRules(ctx, userId, actionRuleType)
	if err != nil {
		zap.L().Error("failed to get action_rules",
			zap.String("action_rule_type", string(actionRuleType)),
			zap.String("user_id", userId),
			zap.Error(err),
		)
		return nil
	}

	// No any rules
	if len(actionRules) == 0 {
		return nil
	}

	// Returns most recent one
	return actionRules[0]
}
