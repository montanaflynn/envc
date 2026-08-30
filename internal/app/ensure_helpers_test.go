package app

// Test-only shortcuts for the envelope mechanics that `envc ensure` drives.

// rewrap brings one file's envelope in line with access (and base after it),
// the way ensure does for a target with nothing else wrong.
func (a *App) rewrap(env string) error {
	if isBase(env) && !a.baseExists() {
		return baseMissingHint()
	}
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	if err := a.rewrapFile(env, f); err != nil {
		return err
	}
	if isBase(env) {
		return nil
	}
	a.stage(env, f)
	return a.resealBase()
}

// rekey gives one file a new data key.
func (a *App) rekey(env string) error {
	if isBase(env) && !a.baseExists() {
		return baseMissingHint()
	}
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	return a.reencryptFile(env, f)
}

// inspect is a dry-run ensure: the problems that remain plus one pseudo
// problem per pending fix, with File set to the target and Msg to the
// effect ("encrypt 1 plaintext secret: S", "update local readers: …").
func (a *App) inspect(env string) ([]Problem, error) {
	was := a.Opts.DryRun
	a.Opts.DryRun = true
	defer func() { a.Opts.DryRun = was }()
	res, err := a.Ensure(env)
	if err != nil {
		return nil, err
	}
	probs := res.Problems
	for _, t := range res.Targets {
		for _, e := range t.Effects {
			probs = append(probs, Problem{File: t.Name, Msg: e})
		}
	}
	return probs, nil
}
