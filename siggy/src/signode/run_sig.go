package main
import (
  "fmt"; "time"; "math/big"; "os"; "bufio"; "sync";
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethschnorr")

/* starts a background run per triple (nmspc time doc) read from stdin.
   omit the parens.
   doc is a bigint as hex.  time is RFC3339 but _ means use default_start.
   returns at end of input and after all started runs have ended. */
func run_sigs(members []member, guests map[int]guest, default_start time.Time) {
  var s *bufio.Scanner = bufio.NewScanner(os.Stdin); s.Split(bufio.ScanWords)
  var wg *sync.WaitGroup = &sync.WaitGroup{}
  for ;s.Scan(); {
    var (run_id_nmspc, tm, doc string)
    run_id_nmspc = s.Text(); if !s.Scan() {break}
    tm = s.Text(); if !s.Scan() {break}
    doc = s.Text()
    wg.Add(1)
    go _run_sig1(wg, members, guests, default_start, run_id_nmspc, tm, doc) }
  var e error=s.Err(); if e!=nil{warn("input error",e)}
  wg.Wait() }

func _run_sig1(wg *sync.WaitGroup, members []member, guests map[int]guest,
               default_start time.Time, run_id_nmspc, tm, doc string) {
  var (t time.Time; e error; doc1 *big.Int; ok bool)
  defer wg.Done()
  if tm=="_" {t=default_start} else
             {t,e=time.Parse(time.RFC3339,tm); if e!=nil {warn(e);return}}
  doc1,ok=big.NewInt(0).SetString(doc,16); if !ok{warn("bad doc");return}
  _run_sig(members, guests, run_id_nmspc, t, doc1) }

func _run_sig(members []member, guests map[int]guest,
              run_id_nmspc string, start time.Time, doc *big.Int) {
  var (gidx int; id string; ok bool; output prot_output; s ethschnorr.Signature)
  id = run_dss(members, guests, "sig"+run_id_nmspc, start, doc)
  fmt.Println("DSS completed run ID", id)
  for gidx, _ = range guests {
    output, ok = pop_output(pc_dss, gidx, id)
    if !ok {fmt.Println("no signature produced", id, gidx)} else
           {s = output.(ethschnorr.Signature); fmt.Println(s)}}}
