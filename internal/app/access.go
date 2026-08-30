package app

import (
	"github.com/montanaflynn/envc/internal/sshkey"
)

// Allow adds names to access and updates the readers.
func (a *App) Allow(env string, names []string) error {
	if err := baseGuard(env); err != nil {
		return err
	}
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return usagef("allow: at least one principal or group name is required")
	}
	for _, name := range names {
		if !a.Roster.IsPrincipal(name) && !a.Roster.IsGroup(name) {
			return usagef("allow: %q is not a principal or group in .envc.yaml", name)
		}
		if !contains(f.Access, name) {
			f.Access = append(f.Access, name)
		}
	}
	a.stage(env, f)
	if err := a.rewrapFile(env, f); err != nil {
		return err
	}
	return a.resealBase()
}

// Deny removes names from access and re-keys the environment so a removed
// reader who still holds the old data key is locked out.
func (a *App) Deny(env string, names []string) error {
	if err := baseGuard(env); err != nil {
		return err
	}
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return usagef("deny: at least one principal or group name is required")
	}
	for _, name := range names {
		if !contains(f.Access, name) {
			return usagef("deny: %q is not on access in %s", name, envPath(env))
		}
		f.Access = remove(f.Access, name)
	}
	a.stage(env, f)
	if err := a.reencryptFile(env, f); err != nil {
		return err
	}
	return a.resealBase()
}

// Who reports who can decrypt env. For base the list is derived: every
// principal of every environment that inherits it.
func (a *App) Who(env string) (Who, error) {
	var principals, access []string
	inherits := false
	if isBase(env) {
		ps, err := a.baseAccess()
		if err != nil {
			return Who{}, err
		}
		principals, access = ps, []string{}
	} else {
		f, err := a.Load(env)
		if err != nil {
			return Who{}, err
		}
		if principals, err = a.Roster.Expand(f.Access); err != nil {
			return Who{}, usagef("%s: %v", envPath(env), err)
		}
		access = append([]string{}, f.Access...)
		if f.InheritsBase() && a.baseExists() {
			if bf, err := a.loadLenient(BaseName); err == nil && bf.Crypto != nil {
				inherits = true
			}
		}
	}
	w := Who{
		Access:       access,
		Derived:      isBase(env),
		InheritsBase: inherits,
		Principals:   principals,
		Keys:         map[string][]string{},
	}
	for _, name := range principals {
		p := a.Roster.Principals[name]
		keys := []string{}
		for _, line := range p.Keys {
			pk, err := sshkey.Parse(line)
			if err != nil {
				keys = append(keys, "invalid: "+err.Error())
				continue
			}
			keys = append(keys, sshkey.Fingerprint(pk))
		}
		if p.Age != "" {
			keys = append(keys, p.Age)
		}
		w.Keys[name] = keys
	}
	return w, nil
}
