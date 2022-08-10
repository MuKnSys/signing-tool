package main
import ("sync"; "time"; "fmt"; "encoding/gob";
        "go.dedis.ch/kyber/v3/share/dkg/rabin")

/* These tables drive the protocol execution */
const (op_start = -1; op_deal = 0; op_response = 1; op_justification = 2;
       op_dkg_final = 3;)
var dkg_steps map[int]func(*protocol_run)bool =
  map[int]func(*protocol_run)bool {
    op_deal: step_deal,
    op_dkg_final: step_vss_done, }
var dkg_processors map[int]func(*protocol_run,Message) =
  map[int]func(*protocol_run,Message) {
    op_deal: process_deal,
    op_response: process_response,
    op_justification: process_justification, }
var dtos []any = []any{DealDTO{}, &dkg.Response{}, JustificationDTO{}}

var (_nc *net_caller
     _threshold int /* T in the DKG scheme */
     _guests map[int]guest
     _members []member )

/* guest index to protocol run id to generator */
var _gens map[int]map[string]*protocol_run =
    make(map[int]map[string]*protocol_run)
var _gens_lck *sync.Mutex = &sync.Mutex{}

func dkg_init(nc *net_caller, threshold int,
              guests map[int]guest, members []member) {
  var (idx int; dto any)
  _nc = nc; _threshold = threshold; _guests = guests; _members = members
  _gens_lck.Lock(); defer _gens_lck.Unlock()
  for idx, _ = range guests { _gens[idx] = make(map[string]*protocol_run) }
  for _, dto = range dtos { gob.Register(dto) } }

/* second result is true if dkg needed creating */
func _ensure_dkg(g guest, run_id string) (*protocol_run,bool) {
  var (result *protocol_run; ok bool)
  _gens_lck.Lock(); defer _gens_lck.Unlock()
  result, ok = _gens[g.index][run_id]
  if ok { return result, false } else
        { return _register_new_dkg(g, run_id), true } }

/* Registers and returns a new DistKeyGenerator for given guest and run_id.
   T is the threshold in the DKG protocol. */
func _register_new_dkg(g guest, run_id string) *protocol_run {
  return _register_dkg(_new_dkg(g, run_id)) }

func _new_dkg(g guest, run_id string) *protocol_run {
  var (d *dkg.DistKeyGenerator; e error)
  d,e = dkg.NewDistKeyGenerator(suite, g.sec, member_pubs(_members), _threshold)
  assert_nil(e)
  return &protocol_run{id: run_id, dat: d, state: op_start, lck: &sync.Mutex{},
                       guest_index: g.index, buffer: make(map[int][]Message),
                       steps: dkg_steps} }

func _register_dkg(run *protocol_run) *protocol_run {
  _gens[(*run).guest_index][(*run).id] = run; return run }

func ensure_active_dkg(g guest, run_id string) *protocol_run {
  var (run *protocol_run; act bool)
  run, act = _ensure_dkg(g, run_id)
  if act {go _run_dkg_timer(run)}
  return run }

const _state_timeout = 100 * time.Millisecond

func _run_dkg_timer(run *protocol_run) {
  var (f func(*protocol_run)bool; ok, sleep bool)
  (*run).lck.Lock()
  for ;(*run).state < op_dkg_final; {
    (*run).state = (*run).state + 1
    f, ok = (*run).steps[(*run).state]
    if ok {sleep = f(run)} else {sleep = true}
    _drain_state_buffer(run)
    if sleep {(*run).lck.Unlock();time.Sleep(_state_timeout);(*run).lck.Lock()}}
  (*run).lck.Unlock() }

func _drain_state_buffer(run *protocol_run) {
  var msg Message
  for _, msg = range (*run).buffer[(*run).state] { _process_msg(run, msg) }
  delete((*run).buffer, (*run).state) }

func (t *SigServer) Receive(msg Message, resp *int) error {
  *resp = 0
  var (g guest; ok bool; run *protocol_run)
  g, ok = _guests[msg.RecipientIndex]
  if !ok {warn("unknown recipient index", msg.RecipientIndex); return nil}
  run = ensure_active_dkg(g, msg.RunId)
  (*run).lck.Lock(); defer (*run).lck.Unlock()
  if msg.Op < (*run).state {
    warn("dropping late message: state/op: ", (*run).state, msg.Op)
  } else if msg.Op > (*run).state {
    //TODO unbounded buffer can allow attacker to fill this computer's RAM
    //fmt.Println("queueing message for future state", msg)
    (*run).buffer[msg.Op] = append((*run).buffer[msg.Op], msg)
  } else {
    _process_msg(run, msg)
  }
  return nil }

func _process_msg(run *protocol_run, msg Message) {
  var (proc func(*protocol_run,Message); ok bool)
  proc, ok = dkg_processors[msg.Op]
  if ok {proc(run, msg)} else { warn("no processor for op", msg.Op) } }

func process_deal(run *protocol_run, msg Message) {
  var (deal *dkg.Deal; err error; resp *dkg.Response)
  deal, err = dto_to_deal(msg.DTO.(DealDTO))
  if err != nil { warn("could not unmarshal deal dto", msg.DTO); return }
  resp, err = _dat_gen(run).ProcessDeal(deal)
  if err != nil { warn("process deal error", err); return }
  broadcast(run, op_response, resp) }

func process_response(run *protocol_run, msg Message) {
  var (j *dkg.Justification; err error)
  j, err = _dat_gen(run).ProcessResponse(msg.DTO.(*dkg.Response))
  if err != nil { warn("process response error", err); return }
  if j == nil { return }
  var dto JustificationDTO
  dto, err = justification_to_dto(j)
  if err != nil { warn("justification marshalling error", err); return }
  broadcast(run, op_justification, dto) }

func process_justification(run *protocol_run, msg Message) {
  var (j *dkg.Justification; err error)
  j, err = dto_to_justification(msg.DTO.(JustificationDTO))
  if err != nil {warn("could not unmarshal justification dto", msg.DTO); return}
  err = _dat_gen(run).ProcessJustification(j)
  warn_if_err(err) }

func step_deal(run *protocol_run) bool {
  var (deals map[int]*dkg.Deal; d *dkg.Deal; idx int; err error; dto DealDTO)
  deals, err = _dat_gen(run).Deals(); warn_if_err(err)
  for idx, d = range deals {
    dto, err = deal_to_dto(d)
    if err != nil {warn("deal marshalling error", err); continue}
    _send(idx,
          Message{RecipientIndex:idx, RunId:(*run).id, Op:op_deal, DTO:dto})}
  return true }

func step_vss_done(run *protocol_run) bool {
  _dat_gen(run).SetTimeout()
  fmt.Println("certified: ", _dat_gen(run).Certified())
  return false }

/* does not send to self */
func broadcast(run *protocol_run, op int, dto any) {
  var m member
  for _, m = range _members {
    if (m.index != (*run).guest_index) {
      _send(m.index,
            Message{RecipientIndex:m.index, RunId:(*run).id, Op:op, DTO:dto})}}}

func _send(member_index int, args any) { _nc.try_send(member_index, args) }

func _dat_gen(run *protocol_run) *dkg.DistKeyGenerator {
  return (*run).dat.(*dkg.DistKeyGenerator) }
