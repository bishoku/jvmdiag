ARG GO_IMAGE=golang:1.27.3-bookworm
ARG RUNTIME_IMAGE=alpine:3.24.3
FROM ${GO_IMAGE} AS builder
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" -o /out/jvmdiag ./cmd/jvmdiag

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates && addgroup -g 10001 jvmdiag && adduser -D -u 10001 -G jvmdiag jvmdiag && mkdir /data && chown 10001:10001 /data
COPY --from=builder /out/jvmdiag /usr/local/bin/jvmdiag
COPY LICENSE NOTICE LICENSE-Go.txt THIRD_PARTY_NOTICES.md /usr/share/licenses/jvmdiag/
COPY internal/server/assets/js/LICENSE.marked.txt /usr/share/licenses/jvmdiag/LICENSE.marked.txt
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_URL=""
LABEL org.opencontainers.image.title="go-jvmdiag" org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${COMMIT}" org.opencontainers.image.source="${SOURCE_URL}" org.opencontainers.image.licenses="Apache-2.0"
ENV HOME=/data
USER 10001:10001
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["jvmdiag"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080", "--multi-user", "--data-dir", "/data"]
