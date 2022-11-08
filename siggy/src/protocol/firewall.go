/* Dependencies: Message, protocol_code
   Exports: fw, make_fw, fw_set_allowance, fw_input */
/* A firewall receives messages at its input and forwards them to its output.
   It knows the time at which connections are initialized, before which it
   unconditionally drops all messages.
   When running, it drops all messages by default.
   You can tell it to make an allowance for a particular protocol run ID.
   An allowance specifies the time at which messages can start being
   buffered, the time at which the buffer may be flushed and new
   messages forwarded directly, and the time at which the allowance is
   to be revoked.
   Replay attacks:
    - While an allowance is in place, you are responsible for preventing them.
    - Once it is removed, you can easily prevent them by never again making an
      allowance for the same run ID, e.g. with timestamped run ID's. */

package main; import ("time"; "sync")

/* states */
const (_fw_dropping,_fw_buffering,_fw_forwarding,_fw_stopped,_nfw int=0,1,2,3,4)
type _allowance struct { buf, start, stop time.Time } /* value */
type fw struct { /* entity */
  _output func(Message)
  _nprots int
  _guests map[int]guest
  _drop_until time.Time /* while connections are still... */
  _drop_all bool        /* ...being set up initially. latch. */
  /* these are indexed by protocol code to guest index to run_id */
  _allowances []map[int]map[string]_allowance
  _state []map[int]map[string]int
  _buffer []map[int]map[string][]Message
  _lck *sync.Mutex
}
const (_fw_buf_max int = 2048)

func make_fw(output func(Message), nprots int, guests map[int]guest,
             drop_until time.Time) *fw {
  var result fw = fw{_output: output,
                     _nprots: nprots,
                     _guests: guests,
                     _drop_until: drop_until,
                     _drop_all: time.Now().Before(drop_until),
                     _allowances: make([]map[int]map[string]_allowance,nprots),
                     _state: make([]map[int]map[string]int,nprots),
                     _buffer: make([]map[int]map[string][]Message,nprots),
                     _lck: &sync.Mutex{}}
  var i int; for i=0;i<nprots;i++ {
    result._allowances[i] = make(map[int]map[string]_allowance)
    result._state[i] = make(map[int]map[string]int)
    result._buffer[i] = make(map[int]map[string][]Message)
    var gidx int; for gidx, _ = range result._guests {
      result._allowances[i][gidx] = make(map[string]_allowance)
      result._state[i][gidx] = make(map[string]int)
      result._buffer[i][gidx] = make(map[string][]Message) } }
  if result._drop_all {
    go func(f *fw) {
      time.Sleep(time.Until(drop_until))
      (*f)._lck.Lock(); (*f)._drop_all = false; (*f)._lck.Unlock() }(&result) }
  return &result }

/* You must not call this when an equivalent allowance is already in place.
   The returned channel is informed about state changes. */
func fw_set_allowance(f *fw, pc protocol_code, gidx int, run_id string,
                      buf, start, stop time.Time) chan int {
  var obs chan int = make(chan int, _nfw)
  (*f)._lck.Lock(); defer (*f)._lck.Unlock()
  var hit bool; _, hit = (*f)._allowances[pc][gidx][run_id]; if hit{return obs}
  (*f)._allowances[pc][gidx][run_id]=_allowance{buf:buf,start:start,stop:stop}
  (*f)._state[pc][gidx][run_id] = _fw_dropping
  go _fw_state_step(f, pc, gidx, run_id, obs)
  return obs }

func _fw_state_step(f *fw,pc protocol_code,gidx int,run_id string,obs chan int){
  (*f)._lck.Lock()
    var allowance _allowance = (*f)._allowances[pc][gidx][run_id]
    _fw_sleep_unlocked_until(f, allowance.buf)
    (*f)._state[pc][gidx][run_id] = _fw_buffering; obs <- _fw_buffering
    _fw_sleep_unlocked_until(f, allowance.start)
    _fw_flush(f, pc, gidx, run_id)
    (*f)._state[pc][gidx][run_id] = _fw_forwarding; obs <- _fw_forwarding
    _fw_sleep_unlocked_until(f, allowance.stop)
    (*f)._state[pc][gidx][run_id] = _fw_stopped; obs <- _fw_stopped
    delete((*f)._allowances[pc][gidx], run_id)
    delete((*f)._state[pc][gidx], run_id)
  (*f)._lck.Unlock() }

func _fw_sleep_unlocked_until(f *fw, tm time.Time) {
  (*f)._lck.Unlock(); time.Sleep(time.Until(tm)); (*f)._lck.Lock(); }

func _fw_flush(f *fw, pc protocol_code, gidx int, run_id string) {
  var m Message
  for _,m = range (*f)._buffer[pc][gidx][run_id] {(*f)._output(m)}
  delete((*f)._buffer[pc][gidx], run_id) }

func fw_input(f *fw) func(Message) {return func(m Message) {_fw_process(f, m)}}
func fw_output(f *fw) func(Message) {return (*f)._output}

func _fw_process(f *fw, m Message) {
  (*f)._lck.Lock(); defer (*f)._lck.Unlock()
  if (*f)._drop_all || !_fw_message_valid(f, m) {return}
  var (state int; ok bool; buf []Message)
  state, ok = (*f)._state[m.ProtocolCode][m.RecipientIndex][m.RunId]
  if ok {
    if state == _fw_buffering {
      buf = (*f)._buffer[m.ProtocolCode][m.RecipientIndex][m.RunId]
      if len(buf) < _fw_buf_max {
        (*f)._buffer[m.ProtocolCode][m.RecipientIndex][m.RunId] = append(buf,m)
      } else { warn("firewall buffer full, dropping message", m) } //TODO DoS
    } else if state == _fw_forwarding { (*f)._output(m) } } }

func _fw_message_valid(f *fw, m Message) bool {
  var ok bool
  if !(0 <= m.ProtocolCode && m.ProtocolCode < (*f)._nprots) {return false}
  _, ok = (*f)._guests[m.RecipientIndex]
  return ok }
