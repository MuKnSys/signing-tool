package main; import ("fmt";"time";"math/big")

func run_dss(guests map[int]guest, msg *big.Int) {
  var (t time.Time; gidx int)
  t = time.Now(); fmt.Println("DKG+DSS start")
  for gidx, _ = range guests { ensure_active_run(pc_dss, gidx, "r0") }
  sleep_for_protocol(pc_dss)
  fmt.Println("DKG+DSS end", time.Since(t)) }
