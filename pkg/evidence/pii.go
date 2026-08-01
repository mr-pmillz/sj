package evidence

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	emailPattern          = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	ssnPattern            = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardPattern           = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	jwtPattern            = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
	apiKeyPattern         = regexp.MustCompile(`(?i)["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?[a-z0-9._~+\-/=]{12,}`)
	phoneContextPattern   = regexp.MustCompile(`(?i)["']?(?:phone(?:[_ -]?number)?|mobile|telephone|tel)["']?\s*[:=]\s*["']?\+?[0-9][0-9 ().-]{6,}[0-9]`)
	birthContextPattern   = regexp.MustCompile(`(?i)["']?(?:date[_ -]?of[_ -]?birth|birth[_ -]?date|dob)["']?\s*[:=]\s*["']?\d{4}-\d{2}-\d{2}`)
	addressContextPattern = regexp.MustCompile(`(?i)["']?(?:address|billing[_ -]?address|shipping[_ -]?address|street[_ -]?address)["']?\s*[:=]\s*["']?\d{1,6}\s+[a-z][a-z0-9 .'-]{1,80}\b(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct)\b`)
	ibanContextPattern    = regexp.MustCompile(`(?i)["']?(?:iban|bank[_ -]?account)["']?\s*[:=]`)
	ibanPattern           = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
)

// DetectPIITypes returns only type labels; matched values never leave this
// package. Payment-card candidates must have a recognized issuer prefix,
// supported length, and valid Luhn checksum to avoid treating long IDs as PII.
func DetectPIITypes(body []byte) []string {
	result := make([]string, 0, 9)
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
	if phoneContextPattern.Match(body) {
		result = append(result, "phone number")
	}
	if birthContextPattern.Match(body) {
		result = append(result, "date of birth")
	}
	if addressContextPattern.Match(body) {
		result = append(result, "postal address")
	}
	if containsContextualIBAN(body) {
		result = append(result, "IBAN")
	}
	return result
}

// IntendedCredentialIssuance reports whether a detected credential appears in
// the expected payload of a successful token-issuing POST endpoint. It is
// deliberately narrow so auth-adjacent debug, profile, and object routes do
// not hide real credential disclosures.
func IntendedCredentialIssuance(method, path string, status int, body []byte, types []string) bool {
	if !strings.EqualFold(strings.TrimSpace(method), "POST") || status < 200 || status >= 300 || len(types) == 0 {
		return false
	}
	for _, value := range types {
		if value != "JWT" && value != "API credential candidate" {
			return false
		}
	}
	segments := strings.Split(strings.Trim(strings.ToLower(strings.TrimSpace(path)), "/"), "/")
	if len(segments) == 0 {
		return false
	}
	switch segments[len(segments)-1] {
	case "auth", "login", "session", "token":
	default:
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return false
	}
	return containsIssuedCredentialField(decoded)
}

func containsIssuedCredentialField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(key)))
			compact := strings.ReplaceAll(normalized, "_", "")
			switch compact {
			case "accesstoken", "apikey", "idtoken", "jwt", "refreshtoken", "sessiontoken", "token":
				if text, ok := child.(string); ok && strings.TrimSpace(text) != "" {
					return true
				}
			}
			if containsIssuedCredentialField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsIssuedCredentialField(child) {
				return true
			}
		}
	}
	return false
}

func containsNonSyntheticEmail(body []byte) bool {
	for _, match := range emailPattern.FindAll(body, -1) {
		address := string(match)
		if !reservedEmailDomain(address) && !publicRoleMailbox(address) {
			return true
		}
	}
	return false
}

func publicRoleMailbox(address string) bool {
	local, _, found := strings.Cut(strings.ToLower(address), "@")
	if !found {
		return false
	}
	local, _, _ = strings.Cut(local, "+")
	local = strings.NewReplacer(".", "", "-", "", "_", "").Replace(local)
	switch local {
	case "admin", "administrator", "billing", "contact", "customerservice", "donotreply",
		"help", "info", "marketing", "noreply", "postmaster", "privacy", "sales",
		"security", "service", "servicioalcliente", "soporte", "support", "webmaster":
		return true
	default:
		return false
	}
}

func reservedEmailDomain(address string) bool {
	_, domain, found := strings.Cut(strings.ToLower(address), "@")
	if !found {
		return true
	}
	switch domain {
	case "example.com", "example.net", "example.org", "localhost", "localhost.localdomain":
		return true
	}
	for _, suffix := range []string{".invalid", ".test", ".example", ".localhost"} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

func containsContextualIBAN(body []byte) bool {
	if !ibanContextPattern.Match(body) {
		return false
	}
	for _, match := range ibanPattern.FindAll(body, -1) {
		if validIBAN(string(match)) {
			return true
		}
	}
	return false
}

func validIBAN(value string) bool {
	value = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	if len(value) < 15 || len(value) > 34 {
		return false
	}
	rearranged := value[4:] + value[:4]
	remainder := 0
	for _, character := range rearranged {
		switch {
		case character >= '0' && character <= '9':
			remainder = (remainder*10 + int(character-'0')) % 97
		case character >= 'A' && character <= 'Z':
			number := int(character-'A') + 10
			remainder = (remainder*100 + number) % 97
		default:
			return false
		}
	}
	return remainder == 1
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
