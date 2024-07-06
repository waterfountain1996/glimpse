build:
	@CGO=0 go build -o ./bin/glimpse ./cmd/glimpse

format:
	@gofmt -w -l .
