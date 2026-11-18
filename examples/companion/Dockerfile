# The build context is the repository root:
#
#	docker build -f examples/companion/Dockerfile -t meshcore-companion .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /companion ./examples/companion
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /companion /companion
# A new named volume inherits this owner, so the nonroot user can write the key.
COPY --from=build --chown=nonroot:nonroot /data /data
EXPOSE 5000
ENTRYPOINT ["/companion", "-listen=0.0.0.0:5000", "-key=/data/companion.key", "-contacts=/data/contacts.json"]
