# Go source files
SRC1 = ssllabs-scan-v4.go
SRC2 = ssllabs-scan-v4-register.go

# Output binaries
BIN1 = ssllabs-scan-v4
BIN2 = ssllabs-scan-v4-register

# Phony targets
.PHONY: all build clean

# Default target
all: build

# Build target
build: $(SRC1) $(SRC2)
	go build -o $(BIN1) $(SRC1)
	go build -o $(BIN2) $(SRC2)

# Clean target
clean:
	rm -f $(BIN1) $(BIN2)
