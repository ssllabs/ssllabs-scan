FROM golang:alpine as build
WORKDIR /go/src/github.com/ssllabs/ssllabs-scan
COPY . .
RUN apk --no-cache add git \
  && go get -u github.com/ssllabs/ssllabs-scan/...

FROM alpine:latest
COPY --from=build /go/bin/ssllabs-scan /bin/ssllabs-scan
RUN apk update \
  && apk upgrade \
  && apk add --no-cache ca-certificates \
  && update-ca-certificates 2>/dev/null || true
ENTRYPOINT ["/bin/ssllabs-scan"]
