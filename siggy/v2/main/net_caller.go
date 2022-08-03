package main
import "fmt"
import "net/rpc"
import mrand "math/rand"
import "time"

/* this will help seamlessly reconnect */
type pathway struct { /* entity */
  addr string
  client *rpc.Client
}

type net_caller struct { /* entity */
  pathways []*pathway    /* one per host incl. own */
  client_map map[int]int /* member index to pathways index */
}

func new_net_caller(addrs []string, client_map map[int]int) *net_caller {
  var (result net_caller; i int; a string)
  result = net_caller{pathways: make([]*pathway, len(addrs)),
                      client_map: client_map}
  for i, a = range addrs { result.pathways[i] = &pathway{addr: a} }
  return &result }

func (nc *net_caller) _member_pathway(member_index int) *pathway {
  return (*nc).pathways[(*nc).client_map[member_index]] }

func (nc *net_caller) member_client(member_index int) *rpc.Client {
  return nc._member_pathway(member_index).client }

// TODO don't block retrying a bad peer forever.
/* This function expects that nobody has been dialled to yet */
func (nc *net_caller) dial_all() {
  var (p *pathway; c *rpc.Client; err error)
  fmt.Print("Dialling all: ")
  for _, p = range (*nc).pathways {
    retry:
      c, err = rpc.DialHTTP("tcp", (*p).addr)
      if err != nil {
        fmt.Print(".")
        time.Sleep(_retry_delay())
        goto retry
      }
      fmt.Print("+")
      (*p).client = c }
  fmt.Println(" complete") }

func _retry_delay() time.Duration {
  return time.Duration(1000 + mrand.Int63n(3000)) * time.Millisecond }
