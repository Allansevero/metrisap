# Habilita recursos avançados do BuildKit, como o cache mount
# syntax=docker/dockerfile:1.4

FROM golang:1.24-alpine3.20 AS builder

RUN apk update && apk add --no-cache gcc musl-dev gcompat

WORKDIR /app
COPY go.mod go.sum ./ 
RUN go mod download

COPY . .
ENV CGO_ENABLED=1

# A linha abaixo foi modificada.
# --mount=type=cache... diz ao Docker para criar um cache persistente para o diretório /root/.cache/go-build
# O Go usa este diretório para armazenar em cache os resultados da compilação.
# Isso acelera drasticamente as compilações futuras e pode resolver erros de build.
RUN --mount=type=cache,target=/root/.cache/go-build go build -o wuzapi

FROM alpine:3.20

RUN apk update && apk add --no-cache \
    ca-certificates \
    netcat-openbsd \
    postgresql-client \
    openssl \
    curl \
    ffmpeg \
    tzdata

ENV TZ="America/Sao_Paulo"
WORKDIR /app

COPY --from=builder /app/wuzapi         /app/
COPY --from=builder /app/static         /app/static/
COPY --from=builder /app/migrations     /app/migrations/
COPY --from=builder /app/repository     /app/repository/
COPY --from=builder /app/wuzapi.service /app/wuzapi.service

RUN chmod +x /app/wuzapi
RUN chmod -R 755 /app
RUN chown -R root:root /app

VOLUME [ "/app/dbdata", "/app/files" ]

ENTRYPOINT ["/app/wuzapi", "--logtype=console", "--color=true"]
