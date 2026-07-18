package evidence

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	emailPattern  = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	ssnPattern    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardPattern   = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	jwtPattern    = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
	apiKeyPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?[a-z0-9_\-]{12,}`)
)

// DetectPIITypes returns only type labels; matched values never leave this
// package. Payment-card candidates must have a recognized issuer prefix,
// supported length, and valid Luhn checksum to avoid treating long IDs as PII.
func DetectPIITypes(body []byte) []string {
	result := make([]string, 0, 5)
	if containsNonSyntheticEmail(body) {
		result = append(result, "email")
	}
	if ssnPattern.Match(body) {
		result = append(result, "US SSN")
	}
	if containsPaymentCard(body) {
		result = append(result, "payment card candidate")
	}
	if jwtPattern.Match(body) {
		result = append(result, "JWT")
	}
	if apiKeyPattern.Match(body) {
		result = append(result, "API credential candidate")
	}
	return result
}

func containsNonSyntheticEmail(body []byte) bool {
	for _, match := range emailPattern.FindAll(body, -1) {
		if !strings.HasSuffix(strings.ToLower(string(match)), ".invalid") {
			return true
		}
	}
	return false
}

func containsPaymentCard(body []byte) bool {
	for _, match := range cardPattern.FindAll(body, -1) {
		digits := strings.NewReplacer(" ", "", "-", "").Replace(string(match))
		if recognizedCardNumber(digits) && validLuhn(digits) {
			return true
		}
	}
	return false
}

func recognizedCardNumber(digits string) bool {
	length := len(digits)
	if length < 13 || length > 19 {
		return false
	}
	prefix := func(size int) (int, bool) {
		if len(digits) < size {
			return 0, false
		}
		value, err := strconv.Atoi(digits[:size])
		return value, err == nil
	}
	firstTwo, _ := prefix(2)
	firstThree, _ := prefix(3)
	firstFour, _ := prefix(4)
	firstSix, _ := prefix(6)
	switch {
	case digits[0] == '4':
		return length == 13 || length == 16 || length == 19
	case length == 16 && (firstTwo >= 51 && firstTwo <= 55 || firstFour >= 2221 && firstFour <= 2720):
		return true
	case length == 15 && (firstTwo == 34 || firstTwo == 37):
		return true
	case (length == 16 || length == 19) && (firstFour == 6011 || firstTwo == 65 || firstThree >= 644 && firstThree <= 649 || firstSix >= 622126 && firstSix <= 622925):
		return true
	case length >= 16 && length <= 19 && firstFour >= 3528 && firstFour <= 3589:
		return true
	case length == 14 && (firstThree >= 300 && firstThree <= 305 || firstTwo == 36 || firstTwo == 38 || firstTwo == 39):
		return true
	default:
		return false
	}
}

func validLuhn(digits string) bool {
	sum := 0
	double := false
	for index := len(digits) - 1; index >= 0; index-- {
		value := int(digits[index] - '0')
		if value < 0 || value > 9 {
			return false
		}
		if double {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
		double = !double
	}
	return sum > 0 && sum%10 == 0
}
