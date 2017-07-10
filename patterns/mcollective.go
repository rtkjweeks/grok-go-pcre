package patterns

var MCollective = map[string]string{
	"MCOLLECTIVEAUDIT": `%{TIMESTAMP_ISO8601:timestamp}:`,
	"MCOLLECTIVE":      `., \[%{TIMESTAMP_ISO8601:timestamp} #%{POSINT:pid}\]%{SPACE}%{LOGLEVEL:event_level}`,
}
