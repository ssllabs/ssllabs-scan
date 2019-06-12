FROM golang:alpine as build
WORKDIR /go/src/github.com/ssllabs/ssllabs-scan
COPY . .
RUN apk update \
  && apk upgrade \
  && apk add --no-cache ca-certificates \
  && update-ca-certificates 2>/dev/null || true
  && apk --no-cache add git \
  && go get -u github.com/ssllabs/ssllabs-scan/...

FROM alpine:latest
COPY --from=build /go/bin/ssllabs-scan /bin/ssllabs-scan
ENTRYPOINT ["/bin/ssllabs-scan"]
