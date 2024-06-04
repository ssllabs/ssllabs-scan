.PHONY: all clean

all: ssllabs-scan-v4 ssllabs-scan-v4-register

ssllabs-scan-v4: ssllabs-scan-v4.go
	go build ssllabs-scan-v4.go

ssllabs-scan-v4-register: ssllabs-scan-v4-register.go
	go build ssllabs-scan-v4-register.go

clean:
	rm ssllabs-scan-v4 ssllabs-scan-v4-register
