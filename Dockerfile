# homenet-smokescreen image: the LAN role/grant wrapper around Smokescreen.
# Built from this fork with vendored modules (hermetic — no module proxy at
# build time). Published as ghcr.io/bennydogg/smokescreen:homenet by
# .github/workflows/homenet-image.yml; homenet's docker-compose.yml pulls it.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags="-s -w" -o /out/smokescreen ./cmd/homenet-smokescreen

FROM alpine:3.20
RUN adduser -D -H -u 4750 smokescreen
COPY --from=build /out/smokescreen /usr/local/bin/smokescreen
USER smokescreen
EXPOSE 4750
ENTRYPOINT ["/usr/local/bin/smokescreen"]
