package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RedisEvalFunc adapts a Redis client's Eval call without adding a dependency.
type RedisEvalFunc func(context.Context, string, []string, ...any) (any, error)
type RedisStore struct {
	eval RedisEvalFunc
	key  string
}

func NewRedisStore(eval RedisEvalFunc, prefix string) (*RedisStore, error) {
	if eval == nil {
		return nil, errors.New("token: Redis Eval function is required")
	}
	if prefix == "" {
		prefix = "goxis:security:refresh"
	}
	return &RedisStore{eval: eval, key: prefix + ":records"}, nil
}

const redisStoreScript = `local old=ARGV[1]; local raw=ARGV[2]; local r=cjson.decode(raw); local now=tonumber(ARGV[3]); local current=redis.call('HGET',KEYS[1],old); if current then return 0 end; redis.call('HSET',KEYS[1],r.token_id,raw); return 1`
const redisRotateScript = `local old=ARGV[1]; local raw=ARGV[2]; local now=tonumber(ARGV[3]); local current=redis.call('HGET',KEYS[1],old); if not current then return 0 end; local e=cjson.decode(current); if e.consumed==true then local all=redis.call('HGETALL',KEYS[1]); for i=1,#all,2 do local x=cjson.decode(all[i+1]); if x.family_id==e.family_id then x.active=false; redis.call('HSET',KEYS[1],all[i],cjson.encode(x)); end end; return 2 end; if e.active~=true or tonumber(e.expires_at)<=now then return 0 end; local n=cjson.decode(raw); if n.family_id~=e.family_id or n.user_id~=e.user_id or n.session_id~=e.session_id then return 0 end; if redis.call('HEXISTS',KEYS[1],n.token_id)==1 then return 0 end; e.active=false; e.consumed=true; redis.call('HSET',KEYS[1],old,cjson.encode(e)); redis.call('HSET',KEYS[1],n.token_id,raw); return 1`
const redisRevokeScript = `local field=ARGV[1]; local value=ARGV[2]; local all=redis.call('HGETALL',KEYS[1]); for i=1,#all,2 do local e=cjson.decode(all[i+1]); if value=='*' or e[field]==value then e.active=false; redis.call('HSET',KEYS[1],all[i],cjson.encode(e)); end end; return 1`

func (s *RedisStore) Store(r RefreshRecord) error {
	if err := validRecord(r); err != nil {
		return err
	}
	b, _ := json.Marshal(redisRecord(r, true, false))
	v, err := s.eval(context.Background(), redisStoreScript, []string{s.key}, r.TokenID, string(b), time.Now().Unix())
	if err != nil {
		return err
	}
	if num(v) != 1 {
		return errors.New("token: duplicate refresh identifier")
	}
	return nil
}
func (s *RedisStore) Rotate(old string, n RefreshRecord) (RotationStatus, error) {
	if err := validRecord(n); err != nil {
		return RotationRejected, err
	}
	b, _ := json.Marshal(redisRecord(n, true, false))
	v, err := s.eval(context.Background(), redisRotateScript, []string{s.key}, old, string(b), time.Now().Unix())
	if err != nil {
		return RotationRejected, err
	}
	if num(v) == 1 {
		return RotationSucceeded, nil
	}
	if num(v) == 2 {
		return RotationReuseDetected, nil
	}
	return RotationRejected, nil
}
func (s *RedisStore) RevokeUser(id string) error {
	_, err := s.eval(context.Background(), redisRevokeScript, []string{s.key}, "user_id", id)
	return err
}
func (s *RedisStore) RevokeSession(id string) error {
	_, err := s.eval(context.Background(), redisRevokeScript, []string{s.key}, "session_id", id)
	return err
}
func redisRecord(r RefreshRecord, active, consumed bool) map[string]any {
	return map[string]any{"token_id": r.TokenID, "family_id": r.FamilyID, "user_id": r.UserID, "session_id": r.SessionID, "expires_at": r.ExpiresAt.Unix(), "active": active, "consumed": consumed}
}
func num(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		var i int64
		_, _ = fmt.Sscan(n, &i)
		return i
	case []byte:
		var i int64
		_, _ = fmt.Sscan(string(n), &i)
		return i
	}
	return 0
}
