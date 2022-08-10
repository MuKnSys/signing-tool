package main; import ("os"; "encoding/json")

type config struct { /* value object */
  dir string
  hostlabels []string
  addrs []string     /* parallel to hostlabels */
  members [][]string /* parallel to addrs */
  pubfiles []string  /* union of sets above */
}

func load_config(conffile, dir string) config {
  var ba []byte; var conf interface{}; var err error
  ba, err = os.ReadFile(conffile); assert_nil(err)
  err = json.Unmarshal(ba, &conf); assert_nil(err)
  var triple []interface{} = conf.([]interface{})
  return config{dir: dir,
                hostlabels: _extract_strings(triple[0]),
                addrs: _extract_strings(triple[1]),
                members: _extract_string_lists(triple[2]),
                pubfiles: _extract_strings(triple[3])} }

func _extract_strings(strings interface{}) []string {
  var i int; var x interface{}
  var xs []interface{} = strings.([]interface{})
  var results []string = make([]string, len(xs))
  for i, x = range xs { results[i] = x.(string) }
  return results }

func _extract_string_lists(lists interface{}) [][]string {
  var i, j int; var xs, y interface{}; var ys []interface{}
  var lists1 []interface{} = lists.([]interface{})
  var results [][]string = make([][]string, len(lists1))
  for i, xs = range lists1 {
    ys = xs.([]interface{})
    results[i] = make([]string, len(ys))
    for j, y = range ys { results[i][j] = y.(string) } }
  return results }
