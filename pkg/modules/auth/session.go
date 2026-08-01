package auth

type SessionVariant string

const (
	SessionValid   SessionVariant = "valid"
	SessionMissing SessionVariant = "missing"
	SessionInvalid SessionVariant = "invalid"
	SessionExpired SessionVariant = "expired"
)

type SessionObservation struct {
	Variant    SessionVariant
	StatusCode int
}

func AnalyzeSession(observations []SessionObservation) []Finding {
	validSuccess := false
	for _, observation := range observations {
		if observation.Variant == SessionValid && successfulStatus(observation.StatusCode) {
			validSuccess = true
			break
		}
	}
	if !validSuccess {
		return nil
	}
	findings := make([]Finding, 0, 3)
	for _, observation := range observations {
		if observation.Variant == SessionValid || !successfulStatus(observation.StatusCode) {
			continue
		}
		var code, summary string
		switch observation.Variant {
		case SessionMissing:
			code, summary = "session-missing-credential-accepted", "Missing-credential control received a successful status"
		case SessionInvalid:
			code, summary = "session-invalid-credential-accepted", "Invalid-token fixture received a successful status"
		case SessionExpired:
			code, summary = "session-expired-credential-accepted", "Expired-token fixture received a successful status"
		default:
			continue
		}
		findings = append(findings, candidate(
			code, SeverityMedium, summary, "session.comparison",
			"Status-only equality is a candidate signal; semantic response and endpoint intent require review.",
		))
	}
	sortFindings(findings)
	return findings
}

func successfulStatus(status int) bool { return status >= 200 && status < 400 }
