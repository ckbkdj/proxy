package platform

import (
	"context"
	"sync"
	"time"
)

const auditProfileCacheTTL = 10 * time.Second

type auditProfileCacheEntry struct {
	profile   AuditProfile
	expiresAt time.Time
}

type auditProfileCacheState struct {
	mutex   sync.RWMutex
	entries map[int64]auditProfileCacheEntry
}

var auditProfileCaches sync.Map

func (e *AuditEngine) profileCache() *auditProfileCacheState {
	state, _ := auditProfileCaches.LoadOrStore(e, &auditProfileCacheState{
		entries: make(map[int64]auditProfileCacheEntry),
	})
	return state.(*auditProfileCacheState)
}

func (e *AuditEngine) getAuditProfile(ctx context.Context, id *int64) (AuditProfile, error) {
	cacheKey := int64(0)
	if id != nil {
		cacheKey = *id
	}
	state := e.profileCache()
	now := time.Now()
	state.mutex.RLock()
	entry, found := state.entries[cacheKey]
	state.mutex.RUnlock()
	if found && entry.expiresAt.After(now) {
		return entry.profile, nil
	}
	profile, err := e.store.GetAuditProfile(ctx, id)
	if err != nil {
		return AuditProfile{}, err
	}
	state.mutex.Lock()
	state.entries[cacheKey] = auditProfileCacheEntry{
		profile:   profile,
		expiresAt: now.Add(auditProfileCacheTTL),
	}
	state.mutex.Unlock()
	return profile, nil
}

func (e *AuditEngine) InvalidateProfiles() {
	state := e.profileCache()
	state.mutex.Lock()
	clear(state.entries)
	state.mutex.Unlock()
}
