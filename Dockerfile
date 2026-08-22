FROM golang:1.26-alpine AS build

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -extldflags=-static" \
      -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api /api
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

USER nonroot:nonroot
EXPOSE 8080

ENV APP_ENV=production \
    HTTP_ADDR=:8080 \
    LOG_FORMAT=json

ENTRYPOINT ["/api"]
