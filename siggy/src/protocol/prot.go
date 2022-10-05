/* abstract core that runs a protocol with timed steps */
package main; import ("sync"; "time"; "encoding/gob"; "reflect")

type protocol_code = int
/* update this list when you create new protocols */
const (pc_dkg, pc_dss protocol_code = 0, 1; _nprots int = 2)

/* These should be increased as membership increases */
/* TODO increase this to allow for actual (non-localhost) network latency */
const _state_timeout time.Duration = 75 * time.Millisecond
/* members' CPUs may run at different speeds. computation may be significant.
   so this should allow slowest supported CPU to do slowest step. */
const _step_timeout time.Duration = 25 * time.Millisecond
/* how long to wait after a stage to be sure all nodes have stopped processing
   input. must be much smaller than a stage's timeout as carved out of that. */
const _pause time.Duration = 5 * time.Millisecond
/* Can allow specifying timeout for each step and each process function. */

const _protocol_timeout_pad time.Duration = 50 * time.Millisecond

type protocol_stage struct { /* value object */
  step func(*protocol_run)
  processor func(*protocol_run,any) /* processes a received message */
  unmarshaller func(any)(any,error)
  dto any
  dto_type reflect.Type
  _timeout time.Duration
}
func ps(step func(*protocol_run), processor func(*protocol_run,any),
        unmarshaller func(any)(any,error), dto any) protocol_stage {
  var d time.Duration; if processor==nil{d=_step_timeout}else{d=_state_timeout}
  return protocol_stage{step,processor,unmarshaller,dto,reflect.TypeOf(dto),d} }

type protocol struct { /* value object. can optimise by referring to address. */
  code protocol_code
  make_kyber_dat func(guest,[]member,int)(any,error) /* constructs Kyber obj */
  stages []protocol_stage                            /* indexed by op code */
}

var _protocols [_nprots]protocol

func register_protocol(p protocol) {
  var (i int)
  for i, _ = range p.stages {
    if p.stages[i].dto != nil { gob.Register(p.stages[i].dto) } }
  _protocols[p.code] = p }

func lookup_protocol(code protocol_code) protocol { return _protocols[code] }

func protocol_timeout(code protocol_code) time.Duration {
  var (result time.Duration; stg protocol_stage)
  for _, stg = range lookup_protocol(code).stages {result = result+stg._timeout}
  return result }

func sleep_for_protocol(code protocol_code) {
  time.Sleep(protocol_timeout(code) + _protocol_timeout_pad) }

func identity_unmarshaller(dto any) (any, error) { return dto, nil }

/* protocol_code to guest index to protocol run id to protocol_run */
var _runs     [_nprots]map[int]map[string]*protocol_run
var _runs_lck [_nprots]map[int]*sync.Mutex
func init() {
  var i int
  for i = 0; i < _nprots; i++ {
    _runs[i]     = make(map[int]map[string]*protocol_run)
    _runs_lck[i] = make(map[int]*sync.Mutex) } }

const _rcv_buf_max int = 10000
var (_threshold int                        /* T in the DKG scheme */
     _members []member
     _guests map[int]guest
     _ncs    [_nprots]map[int]*net_caller  /* indexed by protocol, guest */
     _rcv_qs [_nprots]map[int]chan Message /* indexed by protocol, guest */ )

/* prereq: all _nprots protocols must have registered via register_protocol */
func protocol_start(at time.Time, lay layout, gs map[int]guest, t int) {
  var (i, gidx int; g guest; addresses []string; e error)
  _guests = gs; _threshold = t; _members = lay.members
  for i = 0; i < _nprots; i++ { /* verify that config suits make_kyber_dat */
    for _, g = range _guests {
      _,e = _protocols[i].make_kyber_dat(g,_members,_threshold); assert_nil(e)}}
  for i = 0; i < _nprots; i++ {
    for gidx, _ = range _guests {
      _runs[i][gidx]     = make(map[string]*protocol_run)
      _runs_lck[i][gidx] = &sync.Mutex{} } }
  for i = 0; i < _nprots; i++ {
    _ncs[i] = make(map[int]*net_caller)
    for gidx, _ = range _guests {
      _ncs[i][gidx] = start_net_caller(lay.addrs, lay.member_to_addr)}}
  for i = 0; i < _nprots; i++ {
    _rcv_qs[i] = make(map[int]chan Message)
    for gidx, _ = range _guests {
      _rcv_qs[i][gidx] = make(chan Message, _rcv_buf_max)
      go _run_incoming_queue_consumer(at, _rcv_qs[i][gidx]) } }
  /* now that everything is initialised, it's safe to start serving network */
  addresses = make([]string, 0, len(_guests))
  for _, g = range _guests { addresses = append(addresses, g.addr) }
  start_listeners(_receive_msg, unique(addresses)) }

/* TODO Flaw: Francois points out that ID being random bits is inadequate.
              Attacker can replay somebody's messages from a past run. */
type protocol_run struct { /* entity */
  protocol protocol
  id string         /* globally unique id of a particular run */
  lck *sync.Mutex   /* protects the mutable (non-final) part of the struct */
  nc *net_caller
  members []member
  guest_index int   /* the guest for whom this run object exists */
  kyber_dat any     /* Kyber object */
  prot_dat any      /* a place for protocol specific data */
  _state int        /* op code of messages that we are presently accepting */
  _paused bool      /* whether in post-stage pause, discarding stage inputs */
  _rcvbuf map[int][]Message /* per-op messages for processing in future state */
  _sndbuf map[int][]Message /* per-op messages for sending in future state */
  _abandon bool     /* latch. steps/procs may set to abandon run mid-way */
  terminated bool   /* this becomes true after run is completed or abandoned */
}

func abandon(r *protocol_run) { (*r)._abandon = true }
func abandon_if(r *protocol_run, cond bool) { if cond { abandon(r) } }
func abandoned(r *protocol_run) bool { return (*r)._abandon }

//TODO don't let attack fill our RAM with hundreds of runs
func ensure_active_run(pc protocol_code, gidx int, run_id string) *protocol_run{
  var (run *protocol_run; act bool)
  run, act = _ensure_run(pc, gidx, run_id)
  if act {go _run_timed_steps(run)}
  return run }

/* second result is true if run needed creating */
func _ensure_run(pc protocol_code,gidx int,run_id string) (*protocol_run,bool) {
  var (result *protocol_run; ok bool)
  _runs_lck[pc][gidx].Lock(); defer _runs_lck[pc][gidx].Unlock()
  result, ok = _runs[pc][gidx][run_id]
  if ok { return result, false } else
        { return _register_new_run(pc, gidx, run_id), true } }

func _register_new_run(pc protocol_code, gidx int, run_id string) *protocol_run{
  return _register_run(_new_run(pc, gidx, run_id)) }

func _new_run(pc protocol_code, gidx int, run_id string) *protocol_run {
  var (d any; e error)
  d, e = _protocols[pc].make_kyber_dat(_guests[gidx], _members, _threshold)
  assert_nil(e) /* we verified this at startup in protocol_start */
  return &protocol_run{protocol: _protocols[pc], id: run_id, lck: &sync.Mutex{},
                       nc: _ncs[pc][gidx], members: _members,
                       guest_index: gidx, kyber_dat: d,
                       _state: -1, _paused: false,
                       _rcvbuf: make(map[int][]Message),
                       _sndbuf: make(map[int][]Message)} }

func _register_run(run *protocol_run) *protocol_run {
  _runs[(*run).protocol.code][(*run).guest_index][(*run).id] = run; return run }

func _run_timed_steps(r *protocol_run) {
  var (step func(*protocol_run); msg Message; final int; t time.Time=time.Now())
  (*r).lck.Lock()
  for final = len((*r).protocol.stages)-1; (*r)._state < final; {
    if (*r)._state > -1 {
      (*r)._paused = true; _unlocked_sleep(r, _pause); (*r)._paused = false }
    (*r)._state = (*r)._state + 1
    var stage protocol_stage = (*r).protocol.stages[(*r)._state]
    t = t.Add(stage._timeout)
    _flush_snd_buf(r)
    if !abandoned(r) {
      step = (*r).protocol.stages[(*r)._state].step
      if step != nil { step(r) } }
    for _, msg = range (*r)._rcvbuf[(*r)._state] { _process_msg(r, msg) }
    delete((*r)._rcvbuf, (*r)._state)
    _unlocked_sleep(r, time.Until(t)) }
  (*r).terminated = true
  (*r).lck.Unlock() }

func _unlocked_sleep(r *protocol_run, d time.Duration) {
  (*r).lck.Unlock(); time.Sleep(d); (*r).lck.Lock() }

/* This is called by the network layer when an incoming message is received */
func _receive_msg(msg Message) {
  var (q chan Message; ok bool)
  if !(0 <= msg.ProtocolCode && msg.ProtocolCode < _nprots) {
    warn("bad protocol", msg.ProtocolCode); return }
  if !(0 <= msg.Op && msg.Op < len(_protocols[msg.ProtocolCode].stages)) {
    warn("bad Op", msg.Op); return }
  q, ok = _rcv_qs[msg.ProtocolCode][msg.RecipientIndex]
  if !ok {warn("unknown recipient index", msg.RecipientIndex); return }
  select{case q <- msg:; default:warn("incoming queue full, dropping msg",msg)}}

func _run_incoming_queue_consumer(at time.Time, q chan Message) {
  var (msg Message; run *protocol_run)
  time.Sleep(time.Until(at))
  for ;true; {
    msg = <-q
    run = ensure_active_run(msg.ProtocolCode, msg.RecipientIndex, msg.RunId)
    (*run).lck.Lock()
    if msg.Op < (*run)._state || (msg.Op == (*run)._state && (*run)._paused) {
      warn("dropping late msg: guest/run_id/state/op: ",
           (*run).guest_index, (*run).id, (*run)._state, msg.Op)
    } else if msg.Op > (*run)._state {
      //TODO unbounded buffer can allow attacker to fill this computer's RAM
      //fmt.Println("queueing message for future state", msg)
      // Francois's idea: maybe have only one cell available per peer per step
      (*run)._rcvbuf[msg.Op] = append((*run)._rcvbuf[msg.Op], msg)
    } else {
      _process_msg(run, msg)
    }
    (*run).lck.Unlock() } }

func _process_msg(run *protocol_run, msg Message) {
  var (proc func(*protocol_run,any); stage protocol_stage; arg any; e error)
  if abandoned(run) { return }
  stage = (*run).protocol.stages[msg.Op]
  proc = stage.processor
  if proc == nil { return }
  if reflect.TypeOf(msg.DTO) != stage.dto_type{warn("dto is wrong type");return}
  arg, e = stage.unmarshaller(msg.DTO)
  if e != nil {warn("error unmarshalling DTO. error/dto:", e, msg.DTO); return}
  proc(run, arg) }

/* does not send to self */
func broadcast(run *protocol_run, op int, dto any) {
  var (i int); for i, _ = range (*run).members { _send1(run, i, op, dto) } }

/* does not send to self */
func multicast(midxs []int, run *protocol_run, op int, dto any) {
  var (i int); for _, i = range midxs { _send1(run, i, op, dto) } }

func _send1(run *protocol_run, index int, op int, dto any) {
  if index != (*run).guest_index { send(run, index, op, dto) } }

func send(run *protocol_run, index int, op int, dto any) {
  var m Message = _make_msg(run, index, op, dto)
  if op > (*run)._state {(*run)._sndbuf[op] = append((*run)._sndbuf[op],m)} else
                        {try_send((*run).nc, m.RecipientIndex, m)} }

func _make_msg(run *protocol_run, rcpt_idx int, op int, dto any) Message {
  return Message{ProtocolCode: (*run).protocol.code, RecipientIndex: rcpt_idx,
                 RunId: (*run).id, Op: op, DTO: dto} }

func _flush_snd_buf(r *protocol_run) {
  var m Message
  for _, m = range (*r)._sndbuf[(*r)._state] {
    try_send((*r).nc, m.RecipientIndex, m) }
  delete((*r)._sndbuf, (*r)._state) }
