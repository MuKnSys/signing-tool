package main; import ("fmt"; "net"; "net/rpc"; "net/http")

/* Methods on this type are callable from network. Some are in other files. */
type SigServer int

func start_listeners(addresses []string) {
  var (listener net.Listener; a string; err error)
  var srv *SigServer = new(SigServer)
  rpc.Register(srv)
  rpc.HandleHTTP()
  for _, a = range addresses {
    listener, err = net.Listen("tcp", a); assert_nil(err)
    fmt.Println(a)
    go http.Serve(listener, nil) } }
/* TODO RPC will allow attackers to send huge messages that crash the process */
