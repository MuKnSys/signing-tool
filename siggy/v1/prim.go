package main

func assert_nil(err error) { if err != nil { panic(err); } }

func unique(xs []string) []string {
  var (x string; set map[string]bool = make(map[string]bool))
  for _, x = range xs { set[x] = true }
  var results []string = make([]string, 0, len(set))
  for x, _ = range set { results = append(results, x) }
  return results }
