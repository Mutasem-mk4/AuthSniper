# Build Stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy Go mod file
COPY go.mod ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build a statically linked Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authsniper ./cmd/authsniper/main.go

# Final Stage (Minimal Image)
FROM alpine:latest

# Install root certificates so the tool can talk to HTTPS APIs
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Bring the binary over from the builder stage
COPY --from=builder /app/authsniper .

# Run the sniper
ENTRYPOINT ["./authsniper"]
