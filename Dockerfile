# Builder
FROM golang:alpine as builder
WORKDIR /app

# Install git + SSL ca certificates.
# Git is required for fetching the dependencies.
# Ca-certificates is required to call HTTPS endpoints.
RUN apk update && \
    apk add --no-cache git ca-certificates && \
    update-ca-certificates

# Create appuser.
ENV USER=appuser
ENV UID=10001

# See https://stackoverflow.com/a/55757473/12429735RUN
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Add src files
ADD . .

# Fetch dependencies.
RUN go mod download
RUN go mod verify

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/oidc-forward-auth

# Runner
FROM scratch

# Import the user and group files from the builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy our static executable.
COPY --from=builder /go/bin/oidc-forward-auth /go/bin/oidc-forward-auth

# Use an unprivileged user.
USER appuser:appuser

# Set labels
# Now we DO need these, for the auto-labeling of the image
ARG BUILD_DATE
ARG VCS_REF

# Good docker practice
LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.authors="StiviiK" \
      org.opencontainers.image.source="https://github.com/StiviiK/oidc-forward-auth.git" \
      org.opencontainers.image.revision=$VCS_REF

ENTRYPOINT ["/go/bin/oidc-forward-auth"]