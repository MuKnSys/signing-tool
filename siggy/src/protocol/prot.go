/* abstract core that runs a protocol with timed steps */
package main; import ("sync"; "time"; "encoding/gob"; "reflect")

type protocol_code = int
/* update this list when you create new protocols */
const (pc_dkg, pc_dss protocol_code = 0, 1; _nprots int = 2)
type protocol_stage struct { /* value object */
  step func(*protocol_run)
  processor func(*protocol_run,any) /* processes a received message */
  unmarshaller func(any)(any,error)
  dto any
  dto_type reflect.Type
}
func ps(step func(*protocol_run), processor func(*protocol_run,any),
        unmarshaller func(any)(any,error), dto any) protocol_stage {
  return protocol_stage{step,processor,unmarshaller,dto,reflect.TypeOf(dto)} }
type protocol struct { /* value object. can optimise by referring to address. */
  code protocol_code
  make_kyber_dat func(guest,[]member,int)(any,error) /* constructs Kyber obj */
  op_final int                                       /* steps are 0..op_final */
  stages []protocol_stage                            /* indexed by op code */
}
var _protocols [_nprots]protocol
func register_protocol(p protocol) {
  var (i int)
  for i, _ = range p.stages {
    if p.stages[i].dto != nil { gob.Register(p.stages[i].dto) } }
  _protocols[p.code] = p }

func identity_unmarshaller(dto any) (any, error) { return dto, nil }

/* protocol_code to guest index to protocol run id to protocol_run */
var _runs     [_nprots]map[int]map[string]*protocol_run
var _runs_lck [_nprots]map[int]*sync.Mutex
func init() {
  var i int
  for i = 0; i < _nprots; i++ {
    _runs[i]     = make(map[int]map[string]*protocol_run)
    _runs_lck[i] = make(map[int]*sync.Mutex) } }

const _rcv_buf_max int = 1000
var (_threshold int                        /* T in the DKG scheme */
     _members []member
     _guests map[int]guest
     _ncs    [_nprots]map[int]*net_caller  /* indexed by protocol, guest */
     _rcv_qs [_nprots]map[int]chan Message /* indexed by protocol, guest */ )

/* prereq: all _nprots protocols must have registered via register_protocol */
func protocol_start(layout1 layout, guests map[int]guest, threshold int) {
  var (i, gidx int; g guest; addresses []string)
  _guests = guests; _threshold = threshold; _members = layout1.members
  for i = 0; i < _nprots; i++ {
    for gidx, _ = range _guests {
      _runs[i][gidx]     = make(map[string]*protocol_run)
      _runs_lck[i][gidx] = &sync.Mutex{} } }
  for i = 0; i < _nprots; i++ {
    _ncs[i] = make(map[int]*net_caller)
    for gidx, _ = range _guests {
      _ncs[i][gidx] = start_net_caller(layout1.addrs, layout1.member_to_addr)}}
  for i = 0; i < _nprots; i++ {
    _rcv_qs[i] = make(map[int]chan Message)
    for gidx, _ = range _guests {
      _rcv_qs[i][gidx] = make(chan Message, _rcv_buf_max)
      go _run_incoming_queue_consumer(_rcv_qs[i][gidx]) } }
  /* now that everything is initialised, it's safe to start serving network */
  addresses = make([]string, 0, len(_guests))
  for _, g = range _guests { addresses = append(addresses, g.addr) }
  start_listeners(unique(addresses)) }

type Message struct { /* value object */
  ProtocolCode protocol_code
  RecipientIndex int
  RunId string
  Op int
  DTO any
}

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
  state int         /* op code of messages that we are presently accepting */
  buffer map[int][]Message /* per-op messages for processing in future state */
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
  assert_nil(e)
  return &protocol_run{protocol: _protocols[pc], id: run_id, lck: &sync.Mutex{},
                       nc: _ncs[pc][gidx], members: _members,
                       guest_index: gidx, kyber_dat: d, state: -1,
                       buffer: make(map[int][]Message)} }

func _register_run(run *protocol_run) *protocol_run {
  _runs[(*run).protocol.code][(*run).guest_index][(*run).id] = run; return run }

const _state_timeout time.Duration = 100 * time.Millisecond

func _run_timed_steps(r *protocol_run) {
  var (step func(*protocol_run); msg Message)
  (*r).lck.Lock()
  for ;(*r).state < (*r).protocol.op_final; {
    var p bool
    (*r).state = (*r).state + 1
    if !abandoned(r) {
      step = (*r).protocol.stages[(*r).state].step
      if step != nil {step(r)}
      if !abandoned(r) {
        p = ((*r).protocol.stages[(*r).state].processor != nil)
        if p {
          for _,msg=range(*r).buffer[(*r).state] {
            _process_msg(r,msg)
            if abandoned(r) {break} }}}}
    delete((*r).buffer, (*r).state)
    if (!abandoned(r)) && p {
      (*r).lck.Unlock();time.Sleep(_state_timeout);(*r).lck.Lock()}}
  (*r).terminated = true
  (*r).lck.Unlock() }

/* This is called by Go's RPC library when a message is received from network */
func (t *SigServer) Receive(msg Message, resp *int) error {
  var (q chan Message; ok bool)
  *resp = 0
  if !(0 <= msg.ProtocolCode && msg.ProtocolCode < _nprots) {
    warn("bad protocol", msg.ProtocolCode); return nil }
  if !(0 <= msg.Op && msg.Op <= _protocols[msg.ProtocolCode].op_final) {
    warn("bad Op", msg.Op); return nil }
  q, ok = _rcv_qs[msg.ProtocolCode][msg.RecipientIndex]
  if !ok {warn("unknown recipient index", msg.RecipientIndex); return nil}
  select {case q <- msg:; default:warn("incoming queue full, dropping msg",msg)}
  return nil }

func _run_incoming_queue_consumer(q chan Message) {
  var (msg Message; run *protocol_run)
  for ;true; {
    msg = <-q
    run = ensure_active_run(msg.ProtocolCode, msg.RecipientIndex, msg.RunId)
    (*run).lck.Lock()
    if msg.Op < (*run).state {
      warn("dropping late msg: guest/run_id/state/op: ",
           (*run).guest_index, (*run).id, (*run).state, msg.Op)
    } else if msg.Op > (*run).state {
      //TODO unbounded buffer can allow attacker to fill this computer's RAM
      //fmt.Println("queueing message for future state", msg)
      // Francois's idea: maybe have only one cell available per peer per step
      (*run).buffer[msg.Op] = append((*run).buffer[msg.Op], msg)
    } else {
      _process_msg(run, msg)
    }
    (*run).lck.Unlock() } }

func _process_msg(run *protocol_run, msg Message) {
  var (proc func(*protocol_run,any); u func(any)(any,error); arg any; e error)
  if abandoned(run) { return }
  u = (*run).protocol.stages[msg.Op].unmarshaller
  proc = (*run).protocol.stages[msg.Op].processor
  if reflect.TypeOf(msg.DTO) != (*run).protocol.stages[msg.Op].dto_type {
    warn("dto is wrong type"); return }
  arg, e = u(msg.DTO)
  if e != nil {warn("error unmarshalling DTO. error/dto:", e, msg.DTO); return}
  proc(run, arg) }

/* does not send to self */
func broadcast(run *protocol_run, op int, dto any) {
  var (i int)
  for i, _ = range (*run).members {
    if (i != (*run).guest_index) { send(run, i, op, dto) }}}

/* does not send to self */
func multicast(midxs []int, run *protocol_run, op int, dto any) {
  var (i int)
  for _, i = range midxs {
    if i != (*run).guest_index { send(run, i, op, dto) } } }

func send(run *protocol_run, index int, op int, dto any) {
  try_send((*run).nc, index, _make_msg(run, index, op, dto)) }

func _make_msg(run *protocol_run, rcpt_idx int, op int, dto any) Message {
  return Message{ProtocolCode: (*run).protocol.code, RecipientIndex: rcpt_idx,
                 RunId: (*run).id, Op: op, DTO: dto} }
