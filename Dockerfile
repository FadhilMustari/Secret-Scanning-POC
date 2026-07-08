FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/server .

FROM alpine:3.20
RUN adduser -D -u 10001 appuser
COPY --from=build /out/server /usr/local/bin/server
USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
