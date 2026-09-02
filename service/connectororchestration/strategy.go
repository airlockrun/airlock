package connectororchestration

type Counts struct {
	Held            int
	Active          int
	Succeeded       int
	Failed          int
	Skipped         int
	Total           int
	CanaryTotal     int
	CanaryActive    int
	CanarySucceeded int
	CanaryFailed    int
	CanaryTerminal  int
}

type Decision struct {
	Release int
	Status  string
}

// Decide is the deterministic orchestration state machine. Callers persist its
// release/status decision transactionally; no scheduling state lives in memory.
func Decide(strategy string, maxConcurrency, batchSize, canaryCount, quorum int, counts Counts) Decision {
	terminal := counts.Succeeded + counts.Failed + counts.Skipped
	if strategy == "quorum" {
		if counts.Succeeded >= quorum {
			return Decision{Status: "succeeded"}
		}
		if counts.Succeeded+counts.Active+counts.Held < quorum {
			return Decision{Status: "failed"}
		}
	} else if terminal == counts.Total {
		if counts.Failed > 0 {
			return Decision{Status: "failed"}
		}
		return Decision{Status: "succeeded"}
	}
	capacity := maxConcurrency - counts.Active
	if capacity <= 0 || counts.Held == 0 {
		return Decision{}
	}
	if capacity > counts.Held {
		capacity = counts.Held
	}
	switch strategy {
	case "serial":
		if counts.Active == 0 {
			return Decision{Release: 1}
		}
	case "rolling":
		if counts.Active == 0 {
			if capacity > batchSize {
				capacity = batchSize
			}
			return Decision{Release: capacity}
		}
	case "canary":
		if counts.CanaryFailed > 0 {
			return Decision{Status: "failed"}
		}
		if counts.CanaryTerminal < counts.CanaryTotal {
			remaining := counts.CanaryTotal - counts.CanaryTerminal - counts.CanaryActive
			if capacity > remaining {
				capacity = remaining
			}
			if remaining > 0 {
				return Decision{Release: capacity}
			}
			return Decision{}
		}
		return Decision{Release: capacity}
	case "parallel", "quorum":
		return Decision{Release: capacity}
	}
	return Decision{}
}
