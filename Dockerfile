FROM golang:alpine as build
ARG VERSION

WORKDIR /go/src/github.com/ssllabs/ssllabs-scan
COPY . .
RUN apk add --no-cache git make && make all

FROM alpine:latest
COPY --from=build /go/src/github.com/ssllabs/ssllabs-scan/ssllabs-scan-v3 /usr/bin/
RUN apk update \
  && apk upgrade \
  && apk add --no-cache ca-certificates \
  && update-ca-certificates 2>/dev/null || true

CMD ["ssllabs-scan-v3"]
