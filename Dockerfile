FROM golang:1.23-alpine AS build

# gcc and libc (musl-dev) are required by kaspad
# git is required to build kaspad by commit-hash
RUN apk add gcc musl-dev git

RUN mkdir /build
WORKDIR /build

COPY ./go.mod .
COPY ./go.sum .

RUN go mod download

RUN cp go.mod go.mod.bu
RUN cp go.sum go.sum.bu

COPY . .

# Restore go.mod and go.sum because `COPY . .` overwrote them
RUN mv go.mod.bu go.mod
RUN mv go.sum.bu go.sum
RUN go mod tidy

RUN go env -w GOFLAGS=-mod=mod

RUN GOOS=linux go build -ldflags="-extldflags=-Wl,--allow-multiple-definition" -o merging cmd/rpc/main.go

FROM alpine
WORKDIR /app
COPY --from=build /build/merging /app/

RUN mkdir -p /app/database/migrations
COPY --from=build /build/database/migrations/ /app/database/migrations/
