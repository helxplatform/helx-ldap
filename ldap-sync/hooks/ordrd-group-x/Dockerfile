# Dockerfile

# 1) Builder stage
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o ordrd-group-x .

# 2) Runtime stage
FROM ubuntu:20.04
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /root/
COPY --from=builder /app/ordrd-group-x .
EXPOSE 5001
ENTRYPOINT ["./ordrd-group-x"]
