# Start by building the application.
FROM golang:1.17-bullseye as build

WORKDIR /go/src
COPY . .
RUN go build -o /go/bin/app -v cmd/accounts-oauth/main.go

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian11
COPY --from=build /go/bin/app /
CMD ["/app"]