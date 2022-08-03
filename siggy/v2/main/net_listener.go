package main
import "fmt"
import "net"
import "net/rpc"
import "net/http"

type SigServer int

func (t *SigServer) Ping(data string, response *string) error {
  fmt.Println("received request:", data)
  *response = fmt.Sprintf("Pong %s", data)
  return nil }

func start_listeners(addrs []string) {
  var (listener net.Listener; a string; err error)
  var srv *SigServer = new(SigServer)
  rpc.Register(srv)
  rpc.HandleHTTP()
  for _, a = range addrs {
    listener, err = net.Listen("tcp", a); assert_nil(err)
    fmt.Println(a)
    go http.Serve(listener, nil) } }
