package main; import ("fmt"; "net"; "net/rpc"; "net/http")

/* Methods on this type are callable over the network */
type SigServer int

var _receiver func(Message)

func start_listeners(receiver func(Message), addresses []string) {
  var (listener net.Listener; a string; err error)
  _receiver = receiver
  var srv *SigServer = new(SigServer)
  rpc.Register(srv)
  rpc.HandleHTTP()
  for _, a = range addresses {
    listener, err = net.Listen("tcp", a); assert_nil(err)
    fmt.Println(a)
    go http.Serve(listener, nil) } }
/* TODO RPC will allow attackers to send huge messages that crash the process */

func (t *SigServer) Receive(msg Message, resp *int) error {
  *resp = 0
  _receiver(msg)
  return nil }
