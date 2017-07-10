package patterns

var Redis = map[string]string{
	"REDISTIMESTAMP": `%{MONTHDAY} %{MONTH} %{TIME}`,
	"REDISLOG":       `\[%{POSINT:pid}\] %{REDISTIMESTAMP:timestamp} \* `,
}
