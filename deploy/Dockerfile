# Build stage
FROM golang:1.26 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/p2p-server ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/p2p-server /p2p-server
EXPOSE 8080/tcp
EXPOSE 8080/udp
ENTRYPOINT ["/p2p-server"]
