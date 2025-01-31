package types

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

type ActionRuleType string

const (
	ActionRuleRestrict ActionRuleType = "restrict"
)

type ActionRule struct {
	UserId    string         `db:"user_id"`
	Action    ActionRuleType `db:"action"`
	Expires   *int64         `db:"expires"`
	RulesJson string         `db:"rules_json"`
}

func (s *ActionRule) IsActive(now time.Time) bool {
	// No rule no action
	if s == nil {
		return false
	}
	if s.Expires == nil {
		// The rules forever active
		return true
	}

	return now.Before(time.Unix(*s.Expires, 0))
}

func (s *ActionRule) GetRules() map[string]any {
	if s.RulesJson == "" {
		return nil
	}
	var rules map[string]any
	err := json.Unmarshal([]byte(s.RulesJson), &rules)
	if err != nil {
		zap.L().Error(
			"failed to parse action_rules",
			zap.String("action_rule_type", string(s.Action)),
			zap.String("user_id", s.UserId),
			zap.String("rules_jeson", s.RulesJson),
			zap.Error(err),
		)
		return nil
	}
	return rules
}
