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
  unmarshaller func(any)(any,error) /* must be provided when processor is */
  sender_valid func(any,int)bool    /* must be provided when processor is */
  dto any
  dto_type reflect.Type
  _timeout time.Duration
}
func ps(step func(*protocol_run), processor func(*protocol_run,any),
        unmarshaller func(any)(any,error), sender_valid func(any,int)bool,
        dto any) protocol_stage {
  var d time.Duration; if processor==nil{d=_step_timeout}else{d=_state_timeout}
  return protocol_stage{step, processor, unmarshaller, sender_valid, dto,
                        reflect.TypeOf(dto), d} }

type protocol struct { /* value object. can optimise by referring to address. */
  code protocol_code
  make_kyber_dat func(guest,[]member,int)(any,error) /* constructs Kyber obj */
  stages []protocol_stage                            /* indexed by op code */
  cleanup func(*protocol_run)
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
var _runs         [_nprots]map[int]map[string]*protocol_run
var _runs_lck     [_nprots]map[int]*sync.Mutex
var _term_obs_lck [_nprots]map[int]*sync.Mutex
var _term_obs     [_nprots]map[int]map[string][]chan int /* unspecific value */
func init() {
  var i int
  for i = 0; i < _nprots; i++ {
    _runs[i]         = make(map[int]map[string]*protocol_run)
    _runs_lck[i]     = make(map[int]*sync.Mutex)
    _term_obs[i]     = make(map[int]map[string][]chan int)
    _term_obs_lck[i] = make(map[int]*sync.Mutex) } }

const _rcv_buf_max int = 10000
var (_threshold int                        /* T in the DKG scheme */
     _members []member
     _guests map[int]guest
     _ncs    [_nprots]map[int]*net_caller  /* indexed by protocol, guest */
     _rcv_qs [_nprots]map[int]chan Message /* indexed by protocol, guest */ )

var prot_fw *fw

/* prereq: all _nprots protocols must have registered via register_protocol */
func protocol_start(at time.Time, lay layout, gs map[int]guest, t int) {
  _guests = gs; _threshold = t; _members = lay.members
  _verify_config_suits_make_kyber_dat()
  _init_runs_and_obs()
  _init_outputs()
  _start_net_callers(lay)
  _start_rcv_queue_consumers()
  prot_fw = make_fw(_receive_msg, _nprots, gs, at)
  _start_listeners1() }

func _verify_config_suits_make_kyber_dat() {
  var (i int; g guest; e error)
  for i = 0; i < _nprots; i++ { /* verify that config suits make_kyber_dat */
    for _, g = range _guests {
      _,e=_protocols[i].make_kyber_dat(g,_members,_threshold); assert_nil(e)}}}

func _init_runs_and_obs() {
  var (i, gidx int)
  for i = 0; i < _nprots; i++ {
    for gidx, _ = range _guests {
      _runs[i][gidx]         = make(map[string]*protocol_run)
      _runs_lck[i][gidx]     = &sync.Mutex{}
      _term_obs[i][gidx]     = make(map[string][]chan int)
      _term_obs_lck[i][gidx] = &sync.Mutex{} } } }

func _start_net_callers(lay layout) {
  var (i, gidx int)
  for i = 0; i < _nprots; i++ {
    _ncs[i] = make(map[int]*net_caller)
    for gidx, _ = range _guests {
      _ncs[i][gidx] = start_net_caller(lay.addrs, lay.member_to_addr)}}}

func _start_rcv_queue_consumers() {
  var (i, gidx int)
  for i = 0; i < _nprots; i++ {
    _rcv_qs[i] = make(map[int]chan Message)
    for gidx, _ = range _guests {
      _rcv_qs[i][gidx] = make(chan Message, _rcv_buf_max)
      go _run_incoming_queue_consumer(_rcv_qs[i][gidx]) } } }

func _start_listeners1() {
  var (g guest; addresses []string)
  addresses = make([]string, 0, len(_guests))
  for _, g = range _guests { addresses = append(addresses, g.addr) }
  start_listeners(fw_input(prot_fw), unique(addresses)) }


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

func _delete_run(msg Message) {
  var (pc protocol_code = -msg.ProtocolCode; gidx int = msg.RecipientIndex)
  _runs_lck[pc][gidx].Lock(); defer _runs_lck[pc][gidx].Unlock()
  delete(_runs[pc][gidx], msg.RunId) }

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
  (*r).protocol.cleanup(r)
  (*r).terminated = true
  (*r).lck.Unlock()
  _update_term_observers(r) }

func _unlocked_sleep(r *protocol_run, d time.Duration) {
  (*r).lck.Unlock(); time.Sleep(d); (*r).lck.Lock() }

/* This is called by the network layer when an incoming message is received.
   A negative protocol code is an out-of-band signal to delete the run. */
func _receive_msg(msg Message) {
  if (msg.ProtocolCode < 0) {
    _rcv_qs[-msg.ProtocolCode][msg.RecipientIndex] <- msg; return }
  if !(0 <= msg.Op && msg.Op < len(_protocols[msg.ProtocolCode].stages)) {
    warn("bad Op", msg.Op); return }
  select{case _rcv_qs[msg.ProtocolCode][msg.RecipientIndex] <- msg:;
         default:warn("incoming queue full, dropping msg", msg)}}

func _run_incoming_queue_consumer(q chan Message) {
  for ;true; {
    var (msg Message; run *protocol_run)
    msg = <-q
    if msg.ProtocolCode < 0 { _delete_run(msg); continue; }
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
  if !(0 <= msg.SenderIndex && msg.SenderIndex < len(_members) &&
       stage.sender_valid(arg, msg.SenderIndex)) {
    warn("invalid sender index or imposter"); return }
  proc(run, arg) }

/* does not send to self */
func broadcast(r *protocol_run, op int, dto any) {
  var (i int); for i, _ = range (*r).members { _send1(r, i, op, dto) } }

/* does not send to self */
func multicast(midxs []int, r *protocol_run, op int, dto any) {
  var (i int); for _, i = range midxs { _send1(r, i, op, dto) } }

func _send1(r *protocol_run, index int, op int, dto any) {
  if index != (*r).guest_index { send(r, index, op, dto) } }

func send(r *protocol_run, index int, op int, dto any) {
  var m Message = _make_msg(r, index, op, dto)
  if op > (*r)._state {(*r)._sndbuf[op] = append((*r)._sndbuf[op],m)} else
                      {try_send((*r).nc, m.RecipientIndex, m)} }

func _make_msg(r *protocol_run, rcpt_idx int, op int, dto any) Message {
  return Message{SenderIndex: (*r).guest_index,
                 ProtocolCode: (*r).protocol.code, RecipientIndex: rcpt_idx,
                 RunId: (*r).id, Op: op, DTO: dto} }

func _flush_snd_buf(r *protocol_run) {
  var m Message
  for _, m = range (*r)._sndbuf[(*r)._state] {
    try_send((*r).nc, m.RecipientIndex, m) }
  delete((*r)._sndbuf, (*r)._state) }

/* you should register observers before initiating the run */
func obs_term(p protocol_code, gidx int, run_id string) chan int {
  var result chan int = make(chan int, 1)
  _term_obs_lck[p][gidx].Lock()
    _term_obs[p][gidx][run_id] = append(_term_obs[p][gidx][run_id], result)
  _term_obs_lck[p][gidx].Unlock()
  var (r *protocol_run; hit bool; term bool = false) /* concurrent run */
  _runs_lck[p][gidx].Lock()
    r, hit = _runs[p][gidx][run_id]
  _runs_lck[p][gidx].Unlock()
  if hit { (*r).lck.Lock(); term = r.terminated; (*r).lck.Unlock() }
  if term { _update_term_observers(r) } /* because may have missed update */
  return result }

func _update_term_observers(r *protocol_run) {
  var (pc protocol_code = (*r).protocol.code; gidx int = (*r).guest_index;
       rid string = (*r).id; chans []chan int; c chan int)
  _term_obs_lck[pc][gidx].Lock();
    chans = _term_obs[pc][gidx][rid]
    delete(_term_obs[pc][gidx], rid)
  _term_obs_lck[pc][gidx].Unlock()
  for _, c = range chans { c <- 0; close(c); } }

/* protocol outputs */

type prot_output = any
/* protocol to guest index to run_id to run output */
var _outputs [_nprots]map[int]map[string]prot_output
var _outputs_lcks [_nprots]map[int]*sync.Mutex

func _init_outputs() {
  var (i, gidx int)
  for i = 0; i < _nprots; i++ {
    _outputs[i] = make(map[int]map[string]prot_output)
    _outputs_lcks[i] = make(map[int]*sync.Mutex)
    for gidx, _ = range _guests {
      _outputs[i][gidx] = make(map[string]prot_output)
      _outputs_lcks[i][gidx] = &sync.Mutex{} }}}

func push_output(pc protocol_code, gidx int, run_id string, value prot_output) {
  _outputs_lcks[pc][gidx].Lock(); defer _outputs_lcks[pc][gidx].Unlock()
  _outputs[pc][gidx][run_id] = value }

func pop_output(pc protocol_code, gidx int, run_id string) (prot_output, bool) {
  var (result prot_output; hit bool)
  _outputs_lcks[pc][gidx].Lock(); defer _outputs_lcks[pc][gidx].Unlock()
  result, hit = _outputs[pc][gidx][run_id]
  delete(_outputs[pc][gidx], run_id)
  return result, hit }
