FROM golang:1.18 as builder
WORKDIR /go/src/hmq
COPY . .
RUN CGO_ENABLED=0 go build -o hmq -a -ldflags '-extldflags "-static"' .


FROM alpine
WORKDIR /go/src/hmq
COPY --from=builder /go/src/hmq .
EXPOSE 1883

ENTRYPOINT ["/go/src/hmq/hmq"]
