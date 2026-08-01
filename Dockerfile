FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cindy-enterprise-server ./cmd/server \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cindy-enterprise-server /usr/local/bin/cindy-enterprise-server
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/cindy
COPY --from=build /src/LICENSE /licenses/cindy-enterprise-server/LICENSE
COPY --from=build /src/NOTICE /licenses/cindy-enterprise-server/NOTICE
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cindy-enterprise-server"]
