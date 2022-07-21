package main
import "fmt"
import "net/rpc"
import mrand "math/rand"
import "time"

/* this will help seamlessly reconnect */
type pathway struct {
  addr string
  client *rpc.Client
}

type net_caller struct {
  pathways []*pathway    /* one per host incl. own */
  client_map map[int]int /* member index to pathways index */
}

func (nc *net_caller) member_pathway(member_index int) *pathway {
  return (*nc).pathways[(*nc).client_map[member_index]] }

func (nc *net_caller) append_pathway(addr string, client *rpc.Client) {
  (*nc).pathways = append((*nc).pathways, &pathway{addr: addr, client: client})
}

// TODO don't block retrying a bad peer forever
// Can optimise by not actually dialling own host if only one guest
//   But still allocate a placeholder pathway so net_caller stays consistent */
/* requires that nobody has been dialled to yet */
func (nc *net_caller) dial_all(addrs []string) {
  var a string; var c *rpc.Client; var err error
  for _, a = range addrs {
    retry:
      c, err = rpc.DialHTTP("tcp", a)
      if err != nil {
        fmt.Print(".")
        time.Sleep(time.Duration(1000 + mrand.Int63n(3000)) * time.Millisecond)
        goto retry
      }
      fmt.Print("+")
      nc.append_pathway(a, c) }
  fmt.Println("\ndialled all successfully") }
