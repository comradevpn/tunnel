// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package storage

import (
	"context"
	"time"

	"github.com/vpnhouse/common-lib-go/xerror"
	"go.uber.org/zap"

	"github.com/vpnhouse/tunnel/internal/types"
)

func (storage *Storage) AddActionRule(ctx context.Context, action *types.ActionRule) error {
	query := `
		INSERT INTO
			action_rules(user_id, action, expires, rules_json)
		VALUES(:user_id, :action, :expires, :rules_json)
	`
	_, err := storage.db.NamedExecContext(ctx, query, action)
	if err != nil {
		return xerror.EStorageError("can't insert action_rule", err, zap.Any("action", action))
	}
	return nil
}

func (storage *Storage) DeleteActionRules(userId string, actionRuleType types.ActionRuleType) error {
	query := `
		DELETE FROM
			action_rules
		WHERE
		   user_id = :user_id
		   AND action = :action
	`

	args := map[string]any{
		"user_id": userId,
		"action":  actionRuleType,
	}

	_, err := storage.db.NamedExec(query, args)
	if err != nil {
		return xerror.EStorageError(
			"can't delete action_rule",
			err,
			zap.String("user_id", userId),
			zap.String("action_rule_type", string(actionRuleType)),
		)
	}
	return nil
}

func (storage *Storage) FindActionRules(ctx context.Context, userId string, actionRuleType types.ActionRuleType) ([]*types.ActionRule, error) {
	query := `
		SELECT 
			user_id,
			action,
			expires,
			rules_json
		FROM 
			action_rules
		WHERE
		    user_id = :user_id
			AND action = :action
			AND coalesce(expires, :now) >= :now
		ORDER BY expires DESC
	`

	now := time.Now().UTC()

	args := map[string]any{
		"now":     now.Unix(),
		"user_id": userId,
		"action":  actionRuleType,
	}

	rows, err := storage.db.NamedQueryContext(ctx, query, args)
	if err != nil {
		return nil, xerror.EStorageError(
			"can't read action_rules",
			err,
			zap.Time("now", now),
			zap.String("user_id", userId),
		)
	}
	defer rows.Close()

	var actions []*types.ActionRule
	for rows.Next() {
		var act types.ActionRule
		err = rows.StructScan(&act)
		if err != nil {
			zap.L().Error("can't scan action_rule",
				zap.Error(err),
				zap.String("user_id", userId),
				zap.String("action_rule_type", string(actionRuleType)),
			)
			continue
		}
		actions = append(actions, &act)
	}
	return actions, nil
}

func (storage *Storage) CleanupExpiredActionRules(ctx context.Context) {
	query := `
		DELETE FROM
			action_rules
		WHERE
			coalesce(expires, :now) < :now
	`

	now := time.Now().UTC()

	args := map[string]any{
		"now": now.Unix(),
	}

	res, err := storage.db.NamedExecContext(ctx, query, args)
	if err != nil {
		zap.L().Error(
			"failed to run cleanup action_rules query",
			zap.Time("now", now),
			zap.Error(err),
		)
		return
	}

	count, err := res.RowsAffected()
	if err != nil {
		zap.L().Error(
			"failed to get affected rows after cleanup action_rules",
			zap.Time("now", now),
			zap.Error(err),
		)
		return
	}

	zap.L().Info(
		"cleanup of expired action_rules completed",
		zap.Int64("rows deleted", count),
	)
}
