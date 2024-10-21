FROM --platform=linux/x86_64 golang:latest

WORKDIR /usr/src/app

COPY ./ /usr/src/app
RUN go mod tidy

CMD go run main.go