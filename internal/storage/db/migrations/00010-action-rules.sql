-- +migrate Up
-- +migrate StatementBegin
CREATE TABLE IF NOT EXISTS action_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         VARCHAR(256),
    action          VARCHAR(64),
    expires         INTEGER,
    rules_json      TEXT
);

CREATE INDEX IF NOT EXISTS action_rules_id ON action_rules(id);
CREATE INDEX IF NOT EXISTS action_rules_user_id ON action_rules(user_id);
-- +migrate StatementEnd

-- +migrate Down
-- +migrate StatementBegin
DROP TABLE action_rules;
-- +migrate StatementEnd