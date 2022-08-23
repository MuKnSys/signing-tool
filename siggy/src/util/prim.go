package main; import ("os"; "fmt")

func assert_nil(err error) { if err != nil { panic(err); } }

func warn(a ...any) (int, error) { return fmt.Fprintln(os.Stderr, a...) }

func warn_if_err(err error) { if err != nil { warn(err) } }

func warn_prg(a ...any) { fmt.Fprint(os.Stderr, "bug: "); warn(a...) }

func unique(xs []string) []string {
  var (x string; set map[string]bool = make(map[string]bool))
  for _, x = range xs { set[x] = true }
  var results []string = make([]string, 0, len(set))
  for x, _ = range set { results = append(results, x) }
  return results }
