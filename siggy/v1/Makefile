all: keygen main
clean:
	rm keygen main
keygen: keygen.go base.go file.go prim.go
	go build -o keygen keygen.go base.go file.go prim.go
main: main.go base.go prim.go config.go net_caller.go net_listener.go member.go layout.go file.go
	go build -o main main.go base.go prim.go config.go net_caller.go net_listener.go member.go layout.go file.go
