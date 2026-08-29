FROM golang:1.25-alpine AS build

WORKDIR /src
COPY . .
RUN go build -buildvcs=false -trimpath -o /out/e2e-node ./tests/e2e/cmd/node
RUN go build -buildvcs=false -trimpath -o /out/e2e-vtun-server ./tests/e2e/cmd/vtun_server
RUN go build -buildvcs=false -trimpath -o /out/e2e-multi-node ./tests/e2e/cmd/multi_node

FROM headscale/headscale:v0.29.3 AS headscale

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl
COPY --from=build /out/e2e-node /usr/local/bin/e2e-node
COPY --from=build /out/e2e-vtun-server /usr/local/bin/e2e-vtun-server
COPY --from=build /out/e2e-multi-node /usr/local/bin/e2e-multi-node
COPY --from=headscale /ko-app/headscale /usr/local/bin/headscale
ENTRYPOINT ["/usr/local/bin/e2e-node"]
