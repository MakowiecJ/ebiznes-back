FROM golang:1.22.4

WORKDIR /app

COPY . .

# RUN go mod tidy
RUN go build -o main .

EXPOSE 8080

CMD ["./main"]
