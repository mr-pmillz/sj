package runtime

import (
	"errors"
	"fmt"
	"testing"
)

type partialCoverageAlias struct {
	target *PartialCoverageError
}

func (failure partialCoverageAlias) Error() string {
	return "partial coverage alias"
}

func (failure partialCoverageAlias) As(target any) bool {
	partial, ok := target.(**PartialCoverageError)
	if !ok {
		return false
	}
	*partial = failure.target
	return true
}

func TestIsOnlyPartialCoverageErrorTraversesWrappedAndJoinedErrors(t *testing.T) {
	partialOne := &PartialCoverageError{AssessmentID: "assessment-one", Reason: "one target was unavailable"}
	partialTwo := &PartialCoverageError{AssessmentID: "assessment-two", Reason: "one origin was rate limited"}
	other := errors.New("report write failed")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "direct partial", err: partialOne, want: true},
		{name: "wrapped partial", err: fmt.Errorf("run assessment: %w", partialOne), want: true},
		{name: "custom errors.As partial", err: partialCoverageAlias{target: partialOne}, want: true},
		{name: "joined partials", err: errors.Join(partialOne, fmt.Errorf("wrapped: %w", partialTwo)), want: true},
		{name: "mixed join", err: errors.Join(partialOne, other), want: false},
		{name: "wrapped mixed join", err: fmt.Errorf("workflow: %w", errors.Join(partialOne, other)), want: false},
		{name: "ordinary error", err: other, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsOnlyPartialCoverageError(test.err); got != test.want {
				t.Fatalf("IsOnlyPartialCoverageError(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
