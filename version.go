package sj

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func Version() string {
	return version
}

func BuildInfo() (v, c, d string) {
	return version, commit, date
}
