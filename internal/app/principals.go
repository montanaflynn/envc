package app

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/sshkey"
)

// namePattern mirrors roster's principal/group name rule.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func checkName(kind, name string) error {
	if !namePattern.MatchString(name) {
		return usagef("invalid %s name %q (must match %s)", kind, name, namePattern)
	}
	return nil
}

// keyID returns the fingerprint of an OpenSSH line, or the raw line when it
// does not parse (so unparsable pins still compare by identity).
func keyID(line string) string {
	pk, err := sshkey.Parse(line)
	if err != nil {
		return strings.TrimSpace(line)
	}
	return sshkey.Fingerprint(pk)
}

// envsIncluding returns sorted env names whose expanded access contains
// principal, and separately those whose access list names group directly.
func (a *App) envsIncluding(principal string) ([]string, error) {
	envs, err := a.EnvList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, env := range envs {
		f, err := a.Load(env)
		if err != nil {
			return nil, err
		}
		expanded, err := a.Roster.Expand(f.Access)
		if err != nil {
			return nil, usagef("%s: %v", envPath(env), err)
		}
		if contains(expanded, principal) {
			out = append(out, env)
		}
	}
	return out, nil
}

// envsListing returns sorted env names whose access list contains name verbatim.
func (a *App) envsListing(name string) ([]string, error) {
	envs, err := a.EnvList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, env := range envs {
		f, err := a.Load(env)
		if err != nil {
			return nil, err
		}
		if contains(f.Access, name) {
			out = append(out, env)
		}
	}
	return out, nil
}

// PrincipalAddKeys pins the given public keys (OpenSSH lines) and/or age
// recipient to a new or existing principal.
func (a *App) PrincipalAddKeys(name, github string, keys []string, ageRecipient string) error {
	if err := checkName("principal", name); err != nil {
		return err
	}
	if a.Roster.IsGroup(name) {
		return usagef("principal add: %q is a group; a name cannot be both", name)
	}
	p, exists := a.Roster.Principals[name]
	have := map[string]bool{}
	for _, k := range p.Keys {
		have[keyID(k)] = true
	}
	added := 0
	for _, line := range keys {
		pk, err := sshkey.Parse(line)
		if err != nil {
			return usagef("principal add %s: %v", name, err)
		}
		id := sshkey.Fingerprint(pk)
		if have[id] {
			continue
		}
		have[id] = true
		p.Keys = append(p.Keys, pk.Line)
		added++
	}
	if ageRecipient != "" {
		r, err := crypto.RecipientFromAge(ageRecipient)
		if err != nil {
			return usagef("principal add %s: %v", name, err)
		}
		if p.Age != r.ID {
			p.Age = r.ID
			added++
		}
	}
	if github != "" {
		p.GitHub = github
	}
	if len(p.Keys) == 0 && p.Age == "" {
		return usagef("principal add %s: no keys given", name)
	}
	a.Roster.Principals[name] = p
	if err := a.saveRoster(); err != nil {
		return err
	}
	if !exists || added == 0 {
		return nil
	}
	envs, err := a.envsIncluding(name)
	if err != nil {
		return err
	}
	return a.reseal(envs, false)
}

// PrincipalFetchGitHub returns the supported keys currently published for user.
func (a *App) PrincipalFetchGitHub(ctx context.Context, user string, ed25519Only bool) (keys []string, skipped []string, err error) {
	pks, skipped, err := sshkey.FetchGitHub(ctxOrBackground(ctx), user)
	if err != nil {
		return nil, nil, exitErr(ExitDrift, err)
	}
	keys = []string{}
	for _, pk := range pks {
		if ed25519Only && pk.Type != "ssh-ed25519" {
			entry := pk.Type
			if pk.Comment != "" {
				entry += " " + pk.Comment
			}
			skipped = append(skipped, entry+" (--ed25519-only)")
			continue
		}
		keys = append(keys, pk.Line)
	}
	return keys, skipped, nil
}

// PrincipalRemove drops the principal from roster, groups, and every access
// list; then re-keys the affected environments. Returns the environments
// touched.
func (a *App) PrincipalRemove(name string) (envs []string, err error) {
	if !a.Roster.IsPrincipal(name) {
		return nil, usagef("principal rm: unknown principal %q", name)
	}
	affected, err := a.envsIncluding(name)
	if err != nil {
		return nil, err
	}
	a.lostHint = []string{name} // so resealBase can still name the leaver
	a.Roster.RemovePrincipal(name)
	for _, env := range affected {
		f, err := a.Load(env)
		if err != nil {
			return nil, err
		}
		f.Access = remove(f.Access, name)
		a.stage(env, f)
		if err := a.reencryptFile(env, f); err != nil {
			return nil, err
		}
	}
	// The principal leaves the derived base access too.
	if err := a.resealBase(); err != nil {
		return nil, err
	}
	if err := a.saveRoster(); err != nil {
		return nil, err
	}
	if affected == nil {
		affected = []string{}
	}
	return affected, nil
}

// PrincipalSync refetches GitHub keys for name (or all with github: set) and
// applies pins. Added keys update the readers; removed keys re-key the
// environments that include the principal, so the old key is locked out.
func (a *App) PrincipalSync(ctx context.Context, name string, all bool, ed25519Only bool) ([]KeyChange, error) {
	var targets []string
	if all {
		for n, p := range a.Roster.Principals {
			if p.GitHub != "" {
				targets = append(targets, n)
			}
		}
		sort.Strings(targets)
	} else {
		p, ok := a.Roster.Principals[name]
		if !ok {
			return nil, usagef("principal sync: unknown principal %q", name)
		}
		if p.GitHub == "" {
			return nil, usagef("principal sync: %s has no github: user in .envc.yaml", name)
		}
		targets = []string{name}
	}

	changes := []KeyChange{}
	reencrypt := map[string]bool{} // env → needs a re-key (else a readers update)
	touched := map[string]bool{}
	for _, n := range targets {
		p := a.Roster.Principals[n]
		fetched, _, err := a.PrincipalFetchGitHub(ctx, p.GitHub, ed25519Only)
		if err != nil {
			return nil, err
		}
		fetchedIDs := map[string]bool{}
		for _, line := range fetched {
			fetchedIDs[keyID(line)] = true
		}
		pinnedIDs := map[string]bool{}
		ch := KeyChange{Principal: n, Added: []string{}, Removed: []string{}}
		var kept []string
		for _, line := range p.Keys {
			id := keyID(line)
			pinnedIDs[id] = true
			if fetchedIDs[id] {
				kept = append(kept, line)
			} else {
				ch.Removed = append(ch.Removed, line)
			}
		}
		for _, line := range fetched {
			if !pinnedIDs[keyID(line)] {
				ch.Added = append(ch.Added, line)
				kept = append(kept, line)
			}
		}
		changes = append(changes, ch)
		if len(ch.Added) == 0 && len(ch.Removed) == 0 {
			continue
		}
		p.Keys = kept
		a.Roster.Principals[n] = p
		if len(ch.Removed) > 0 {
			a.lostHint = append(a.lostHint, n+"'s old key") // names the dropped key in re-key effects
		}
		envs, err := a.envsIncluding(n)
		if err != nil {
			return nil, err
		}
		for _, env := range envs {
			touched[env] = true
			if len(ch.Removed) > 0 {
				reencrypt[env] = true
			}
		}
	}
	if probs := a.Roster.Validate(); len(probs) > 0 {
		return nil, usagef("%s: %s", roster.FileName, joinRosterProblems(probs))
	}
	var envs []string
	for env := range touched {
		envs = append(envs, env)
	}
	sort.Strings(envs)
	for _, env := range envs {
		if err := a.reseal([]string{env}, reencrypt[env]); err != nil {
			return nil, err
		}
	}
	if err := a.saveRoster(); err != nil {
		return nil, err
	}
	return changes, nil
}

// GroupSet creates or replaces a group's members.
func (a *App) GroupSet(name string, members []string) error {
	if err := checkName("group", name); err != nil {
		return err
	}
	if a.Roster.IsPrincipal(name) {
		return usagef("group add: %q is a principal; a name cannot be both", name)
	}
	var list []string
	for _, m := range members {
		if !a.Roster.IsPrincipal(m) {
			return usagef("group add %s: %q is not a principal", name, m)
		}
		if !contains(list, m) {
			list = append(list, m)
		}
	}
	if list == nil {
		list = []string{}
	}
	old, exists := a.Roster.Groups[name]
	a.Roster.Groups[name] = list
	if !exists {
		return a.saveRoster()
	}
	removed := false
	for _, m := range old {
		if !contains(list, m) {
			removed = true
		}
	}
	envs, err := a.envsListing(name)
	if err != nil {
		return err
	}
	if err := a.reseal(envs, removed); err != nil {
		return err
	}
	return a.saveRoster()
}

// GroupAddMember adds and updates the readers of environments listing the group.
func (a *App) GroupAddMember(group, principal string) ([]string, error) {
	members, ok := a.Roster.Groups[group]
	if !ok {
		return nil, usagef("group add-member: unknown group %q", group)
	}
	if !a.Roster.IsPrincipal(principal) {
		return nil, usagef("group add-member %s: %q is not a principal", group, principal)
	}
	if contains(members, principal) {
		return []string{}, nil
	}
	a.Roster.Groups[group] = append(members, principal)
	envs, err := a.envsListing(group)
	if err != nil {
		return nil, err
	}
	if err := a.reseal(envs, false); err != nil {
		return nil, err
	}
	if err := a.saveRoster(); err != nil {
		return nil, err
	}
	if envs == nil {
		envs = []string{}
	}
	return envs, nil
}

// GroupRemoveMember removes and re-keys environments listing the group.
func (a *App) GroupRemoveMember(group, principal string) ([]string, error) {
	members, ok := a.Roster.Groups[group]
	if !ok {
		return nil, usagef("group rm-member: unknown group %q", group)
	}
	if !contains(members, principal) {
		return nil, usagef("group rm-member %s: %q is not a member", group, principal)
	}
	a.Roster.Groups[group] = remove(members, principal)
	envs, err := a.envsListing(group)
	if err != nil {
		return nil, err
	}
	if err := a.reseal(envs, true); err != nil {
		return nil, err
	}
	if err := a.saveRoster(); err != nil {
		return nil, err
	}
	if envs == nil {
		envs = []string{}
	}
	return envs, nil
}

// GroupRemove deletes the group; errors if any environment lists it on access.
func (a *App) GroupRemove(name string) error {
	if !a.Roster.IsGroup(name) {
		return usagef("group rm: unknown group %q", name)
	}
	envs, err := a.envsListing(name)
	if err != nil {
		return err
	}
	if len(envs) > 0 {
		return usagef("group rm %s: still on access in %s; run `envc deny ENV %s` first", name, joinComma(envs), name)
	}
	delete(a.Roster.Groups, name)
	return a.saveRoster()
}
