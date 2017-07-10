package patterns

// Default postgresql pg_log format pattern
var PostgreSQL = map[string]string{
	"POSTGRESQL": `%{DATESTAMP:timestamp} %{TZ} %{DATA:user_id} %{GREEDYDATA:connection_id} %{POSINT:pid}`,
}
