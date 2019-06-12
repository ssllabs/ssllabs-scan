FROM golang:alpine as build
WORKDIR /go/src/github.com/ssllabs/ssllabs-scan
COPY . .
RUN apk --no-cache add git \
  && go get -u github.com/ssllabs/ssllabs-scan/...

FROM alpine:latest
COPY --from=build /go/bin/ssllabs-scan /bin/ssllabs-scan
ENTRYPOINT ["/bin/ssllabs-scan"]
