// Package all registers every built-in destination. Import it for side
// effects from the binary entrypoint (cli) so `sync`, `diff`, and `check`
// can resolve sync.<env>.<name> blocks.
package all

import (
	_ "github.com/montanaflynn/envc/internal/destination/convex"
	_ "github.com/montanaflynn/envc/internal/destination/dotenv"
	_ "github.com/montanaflynn/envc/internal/destination/github"
	_ "github.com/montanaflynn/envc/internal/destination/vercel"
)
