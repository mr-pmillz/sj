//go:build !unix

package report

import (
	"fmt"
	"os"
)

// Platforms without atomic no-follow/non-blocking open support fail closed
// when root-confined report loading is requested. Unconfined CLI loading uses
// the ordinary regular-file path in openReportInput.
func secureOpenRootFile(_ *os.Root, _ string) (*os.File, error) {
	return nil, fmt.Errorf("secure root-confined report loading is unsupported on this platform")
}
