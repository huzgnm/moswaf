package main

// What the agent tells the rest of the system about itself.
//
// The dashboard can see a ban, because the ban lives in the proxy's own memory.
// It cannot see a kernel rule: that is on the host, in another process, behind a
// privilege boundary the proxy deliberately does not cross. So everything the
// dashboard knows about kernel enforcement, it knows because this file said so.
//
// Which makes the failure mode worth naming: a report that is optimistic is worse
// than no report at all. "In the kernel" here means nft accepted the element, not
// that we asked for it - an address that was refused is published as refused, and
// an address whose removal failed is published as an orphan rather than quietly
// dropped from the list. Nothing here rounds towards "it worked".

import (
	"context"
	"log"
	"net/netip"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyApplied = "moswaf:kernel_applied"
	keyRefused = "moswaf:kernel_refused"
	keyOrphans = "moswaf:kernel_orphans"
	keyHealth  = "moswaf:kernel_agent"
)

// orphanReport caps how many un-removable addresses are published.
//
// A hundred examples of a fault say the same thing as ten thousand, and the list
// is read by a page that has to render it.
const orphanReport = 100

// expiry keeps every published key tied to the agent being alive.
//
// Four reconcile intervals: long enough that one slow cycle does not make the
// agent look dead, short enough that a stopped agent stops being reported as
// present. Without this a crashed agent would leave its last cheerful report in
// Redis forever, and the dashboard would show a protected machine.
func (a *agent) expiry() time.Duration {
	return a.cfg.resyncEvery * 4
}

// noteApplied records that this address is in the kernel set, keeping the
// timestamp of when it first got there.
//
// HSetNX rather than HSet: "since" means since the address was first dropped, and
// the reconcile re-adds every element once a minute to refresh its kernel
// timeout. Overwriting on each of those would make every rule look newly created,
// and the one question the timestamp exists to answer - has this been in effect
// long enough to matter - could never be answered.
func (a *agent) noteApplied(ctx context.Context, addr netip.Addr) {
	ip := addr.String()
	pipe := a.rdb.Pipeline()
	pipe.HSetNX(ctx, keyApplied, ip, strconv.FormatInt(time.Now().Unix(), 10))
	// An address cannot be both refused and applied. Whichever happened last is
	// the truth, so the other is cleared rather than left to contradict it.
	pipe.HDel(ctx, keyRefused, ip)
	pipe.Expire(ctx, keyApplied, a.expiry())
	if _, err := pipe.Exec(ctx); err != nil && ctx.Err() == nil {
		log.Printf("moswaf-kbans: could not publish that %s is dropped: %v", ip, err)
	}
}

func (a *agent) noteRefused(ctx context.Context, addr netip.Addr, why string) {
	ip := addr.String()
	pipe := a.rdb.Pipeline()
	pipe.HSet(ctx, keyRefused, ip, why)
	pipe.HDel(ctx, keyApplied, ip)
	// Refusals outlive the ban that prompted them on purpose. The useful moment to
	// read one is after somebody notices an address is not being dropped, which is
	// not the same moment the refusal happened.
	pipe.Expire(ctx, keyRefused, a.expiry())
	if _, err := pipe.Exec(ctx); err != nil && ctx.Err() == nil {
		log.Printf("moswaf-kbans: could not publish the refusal for %s: %v", ip, err)
	}
}

// forget removes one address from everything this agent publishes.
//
// Called only after the kernel removal succeeded. Calling it on a failed removal
// would produce the exact state this whole file exists to prevent: an address the
// dashboard shows as free while the kernel goes on discarding its packets.
func (a *agent) forget(ctx context.Context, addr netip.Addr) {
	ip := addr.String()
	pipe := a.rdb.Pipeline()
	pipe.HDel(ctx, keyApplied, ip)
	pipe.HDel(ctx, keyRefused, ip)
	if _, err := pipe.Exec(ctx); err != nil && ctx.Err() == nil {
		log.Printf("moswaf-kbans: could not publish the release of %s: %v", ip, err)
	}
}

func (a *agent) forgetAll(ctx context.Context) {
	if err := a.rdb.Del(ctx, keyApplied, keyRefused, keyOrphans).Err(); err != nil && ctx.Err() == nil {
		log.Printf("moswaf-kbans: could not publish the release of every address: %v", err)
	}
}

// publishState replaces the applied set with what the kernel actually holds.
//
// Called at the end of a reconcile, from a fresh read of the nftables set rather
// than from the list of addresses we meant to add. The difference shows up
// precisely when something went wrong, which is the only time anybody reads this.
//
// `orphans` are addresses the kernel is still dropping although nothing is banned
// at them any more - normally none, because the reconcile removes them, so a
// non-empty list means a removal failed and somebody is being refused for a
// reason the dashboard can otherwise not account for.
func (a *agent) publishState(ctx context.Context, have map[netip.Addr]int, orphans []netip.Addr) {
	now := strconv.FormatInt(time.Now().Unix(), 10)

	// Written to a scratch key and renamed over the live one, so a reader never
	// sees a half-built set. During a flood the dashboard is being refreshed every
	// few seconds against a set that is being rewritten every minute; without this
	// some of those refreshes would land mid-write and report enforcement missing
	// for addresses that have it.
	scratch := keyApplied + ":building"
	prev := a.rdb.HGetAll(ctx, keyApplied).Val()

	pipe := a.rdb.Pipeline()
	pipe.Del(ctx, scratch)
	if len(have) > 0 {
		fields := make([]any, 0, len(have)*2)
		for addr := range have {
			ip := addr.String()
			since, ok := prev[ip]
			if !ok {
				since = now
			}
			fields = append(fields, ip, since)
		}
		pipe.HSet(ctx, scratch, fields...)
		pipe.Expire(ctx, scratch, a.expiry())
		pipe.Rename(ctx, scratch, keyApplied)
	} else {
		// RENAME on a missing key is an error in Redis, and an empty hash does not
		// exist. Nothing in the kernel is expressed by the key being absent, which
		// is what a reader with no agent sees too - the same answer either way.
		pipe.Del(ctx, keyApplied)
	}

	pipe.Del(ctx, keyOrphans)
	if len(orphans) > 0 {
		list := orphans
		if len(list) > orphanReport {
			list = list[:orphanReport]
		}
		vals := make([]any, 0, len(list))
		for _, addr := range list {
			vals = append(vals, addr.String())
		}
		pipe.RPush(ctx, keyOrphans, vals...)
		pipe.Expire(ctx, keyOrphans, a.expiry())
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil && ctx.Err() == nil {
		log.Printf("moswaf-kbans: could not publish the kernel state: %v", err)
	}
}
