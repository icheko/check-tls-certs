
check-tls-certs:
	go build -o check-tls-certs main.go

clean:
	rm check-tls-certs

rebuild: clean check-tls-certs

install:
	sudo -E go install

uninstall:
	sudo -E rm -fv "${GOBIN}/check-tls-certs"
	ls -al "${GOBIN}"