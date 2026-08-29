FROM golang:1.25-alpine AS build

WORKDIR /src
COPY . .
RUN go build -buildvcs=false -trimpath -o /out/e2e-node ./tests/e2e/cmd/node

FROM headscale/headscale:v0.29.3 AS headscale

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl
COPY --from=build /out/e2e-node /usr/local/bin/e2e-node
COPY --from=headscale /ko-app/headscale /usr/local/bin/headscale
ENTRYPOINT ["/usr/local/bin/e2e-node"]
