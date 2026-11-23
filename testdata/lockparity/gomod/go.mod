module example.com/app

go 1.20

require (
	github.com/gin-gonic/gin v1.7.0
	golang.org/x/net v0.7.0 // indirect
	github.com/old/mod v1.0.0
)

replace github.com/old/mod => golang.org/x/text v0.3.7
