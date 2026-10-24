package token

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type SQLDialect string

const (
	Postgres SQLDialect = "postgres"
	MySQL    SQLDialect = "mysql"
)

// SQLStore uses database/sql; import the driver for your chosen database in the
// application. It does not install or select a driver itself.
type SQLStore struct {
	db      *sql.DB
	dialect SQLDialect
	table   string
}

func NewSQLStore(db *sql.DB, dialect SQLDialect) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("token: SQL database is required")
	}
	if dialect != Postgres && dialect != MySQL {
		return nil, errors.New("token: SQL dialect must be postgres or mysql")
	}
	return &SQLStore{db: db, dialect: dialect, table: "goxis_refresh_tokens"}, nil
}

// SchemaSQL returns the table definition for the selected database.
func (s *SQLStore) SchemaSQL() string {
	if s.dialect == Postgres {
		return `CREATE TABLE IF NOT EXISTS goxis_refresh_tokens (token_id VARCHAR(64) PRIMARY KEY, family_id VARCHAR(64) NOT NULL, user_id VARCHAR(255) NOT NULL, session_id VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL, active BOOLEAN NOT NULL, consumed BOOLEAN NOT NULL)`
	}
	return `CREATE TABLE IF NOT EXISTS goxis_refresh_tokens (token_id VARCHAR(64) PRIMARY KEY, family_id VARCHAR(64) NOT NULL, user_id VARCHAR(255) NOT NULL, session_id VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL, active BOOLEAN NOT NULL, consumed BOOLEAN NOT NULL)`
}
func (s *SQLStore) q(n int) string {
	if s.dialect == Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
func (s *SQLStore) Store(r RefreshRecord) error {
	if err := validRecord(r); err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO %s (token_id,family_id,user_id,session_id,expires_at,active,consumed) VALUES (%s,%s,%s,%s,%s,%s,%s)", s.table, s.q(1), s.q(2), s.q(3), s.q(4), s.q(5), s.q(6), s.q(7))
	_, err := s.db.Exec(q, r.TokenID, r.FamilyID, r.UserID, r.SessionID, r.ExpiresAt.Unix(), true, false)
	return err
}
func (s *SQLStore) Rotate(old string, n RefreshRecord) (RotationStatus, error) {
	if err := validRecord(n); err != nil {
		return RotationRejected, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return RotationRejected, err
	}
	defer tx.Rollback()
	sel := fmt.Sprintf("SELECT family_id,user_id,session_id,active,consumed,expires_at FROM %s WHERE token_id=%s", s.table, s.q(1))
	var family, user, session string
	var active, consumed bool
	var exp int64
	err = tx.QueryRow(sel, old).Scan(&family, &user, &session, &active, &consumed, &exp)
	if err == sql.ErrNoRows {
		return RotationRejected, nil
	}
	if err != nil {
		return RotationRejected, err
	}
	if consumed {
		_, err = tx.Exec(fmt.Sprintf("UPDATE %s SET active=%s WHERE family_id=%s", s.table, s.q(1), s.q(2)), false, family)
		if err != nil {
			return RotationRejected, err
		}
		if err = tx.Commit(); err != nil {
			return RotationRejected, err
		}
		return RotationReuseDetected, nil
	}
	if !active || exp <= time.Now().Unix() || family != n.FamilyID || user != n.UserID || session != n.SessionID {
		return RotationRejected, nil
	}
	upd := fmt.Sprintf("UPDATE %s SET active=%s,consumed=%s WHERE token_id=%s AND active=%s AND consumed=%s", s.table, s.q(1), s.q(2), s.q(3), s.q(4), s.q(5))
	res, err := tx.Exec(upd, false, true, old, true, false)
	if err != nil {
		return RotationRejected, err
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return RotationRejected, nil
	}
	ins := fmt.Sprintf("INSERT INTO %s (token_id,family_id,user_id,session_id,expires_at,active,consumed) VALUES (%s,%s,%s,%s,%s,%s,%s)", s.table, s.q(1), s.q(2), s.q(3), s.q(4), s.q(5), s.q(6), s.q(7))
	if _, err = tx.Exec(ins, n.TokenID, n.FamilyID, n.UserID, n.SessionID, n.ExpiresAt.Unix(), true, false); err != nil {
		return RotationRejected, err
	}
	if err = tx.Commit(); err != nil {
		return RotationRejected, err
	}
	return RotationSucceeded, nil
}
func (s *SQLStore) RevokeUser(id string) error {
	_, err := s.db.Exec(fmt.Sprintf("UPDATE %s SET active=%s WHERE user_id=%s", s.table, s.q(1), s.q(2)), false, id)
	return err
}
func (s *SQLStore) RevokeSession(id string) error {
	_, err := s.db.Exec(fmt.Sprintf("UPDATE %s SET active=%s WHERE session_id=%s", s.table, s.q(1), s.q(2)), false, id)
	return err
}
