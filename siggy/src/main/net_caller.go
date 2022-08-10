package main; import ("net/rpc"; mrand "math/rand"; "time")

const _msg_max = 1000
/* outgoing messages (upto _msg_max) will be buffered during these attempts */
const _grace_conn_attempts = 5

type net_caller struct { /* entity */
  queues []chan any      /* one per host incl. own */
  client_map map[int]int /* member index to queues index */
}

func (nc *net_caller) _queue(member_index int) chan any {
  return (*nc).queues[(*nc).client_map[member_index]] }

func (nc *net_caller) try_send(member_index int, msg any) {
  select {
    case nc._queue(member_index) <- msg: ;
    default: warn("queue full, dropping message", msg) } }

func new_net_caller(addrs []string, client_map map[int]int) *net_caller {
  var (nc net_caller; i int; a string)
  nc = net_caller{queues: make([]chan any, len(addrs)), client_map: client_map}
  for i, a = range addrs {
    nc.queues[i] = make(chan any, _msg_max)
    go _run_queue_consumer(a, nc.queues[i]) }
  return &nc }

/* This is a long running thread consuming from a buffered message queue
   and forwarding messages to a network peer. If for an extended time
   the connection fails to be established or goes down then consumed
   messages are discarded during that time. */
func _run_queue_consumer(addr string, msg_ch chan any) {
  var (c *rpc.Client; resp_ign int; err error; msg any; pushed_back bool)
  var conn_ch chan *rpc.Client = make(chan *rpc.Client)
  pushed_back = false
  for ;true; {
    go _run_connector(addr, conn_ch)
    c = <-conn_ch /* while blocked here, msg_ch is buffering messages */
    if c == nil {
      /* drop messages until connected */
      loop:
      for ;true; {
        if pushed_back {pushed_back = false} else {msg = <-msg_ch}
        select {
          case c = <-conn_ch: break loop
          default: warn("dropping message while disconnected", msg) } }
    } else {
      if pushed_back {pushed_back = false} else {msg = <-msg_ch} }
    for ;true; {
      err = c.Call("SigServer.Receive", msg, &resp_ign)
      if err != nil {
        warn(err);c.Close();pushed_back=true;time.Sleep(_retry_delay());break }
      msg = <-msg_ch } } }

/* publishes connection, or one interim nil followed eventually by connection.*/
func _run_connector(addr string, conn_ch chan *rpc.Client) {
  var (failed_before bool; c *rpc.Client; d time.Duration)
  failed_before = false
  for d = 4 * _retry_delay(); true; d = _min(2*d, 5*time.Minute) {
    c = _try_connect(_grace_conn_attempts, addr)
    if (c != nil) {conn_ch <- c; break}
    if !failed_before {failed_before = true; conn_ch <- nil}
    time.Sleep(d) } }

func _min(x, y time.Duration) time.Duration {if x<y {return x} else {return y}}

/* returns nil on failure */
func _try_connect(attempts int, addr string) *rpc.Client {
  var (c *rpc.Client; i int; err error)
  for i = 0; i < attempts; i++ {
    if (i > 0) {time.Sleep(_retry_delay())}
    c, err = rpc.DialHTTP("tcp", addr)
    if err != nil {c = nil} else {break} }
  return c }

func _retry_delay() time.Duration {
  return time.Duration(1000 + mrand.Int63n(3000)) * time.Millisecond }
