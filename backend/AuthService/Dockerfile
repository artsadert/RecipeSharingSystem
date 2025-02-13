FROM golang:1.23




COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /docker-application


EXPOSE 8080


CMD ["/docker-application"]

