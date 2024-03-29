package main; import ("os";"io/fs";"strings";"fmt";"encoding";"encoding/gob")

func save_to_temp(b encoding.BinaryMarshaler, file_prefix string) {
  var output *os.File; var ba []byte; var err error
  ba, err = b.MarshalBinary(); assert_nil(err)
  output = _create_temp(file_prefix)
  _, err = output.Write(ba); assert_nil(err)
  assert_nil(output.Close()) }

func save_gob_to_temp(x any, file_prefix string) {
  var (output *os.File; e error; enc *gob.Encoder)
  output = _create_temp(file_prefix)
  enc = gob.NewEncoder(output)
  e = enc.Encode(x); assert_nil(e)
  assert_nil(output.Close()) }

func load_gob(x any, infile string) {
  var (f *os.File; e error; dec *gob.Decoder)
  f, e = os.Open(infile); assert_nil(e)
  dec = gob.NewDecoder(f)
  e = dec.Decode(x); assert_nil(e)
  assert_nil(f.Close()) }

func _create_temp(prefix string) *os.File {
  var result *os.File; var err error
  result, err = os.CreateTemp("", prefix); assert_nil(err)
  fmt.Println(result.Name())
  return result }

/* loads from dir each file whose name matches prefix */
func slurp_all(dir, prefix string) [][]byte {
  var dirents, selection []os.DirEntry; var err error
  var i int; var e os.DirEntry; var names []string
  dirents, err = os.ReadDir(dir); assert_nil(err)
  selection = _filter_prefix(dirents, prefix)
  names = make([]string, len(selection))
  for i, e = range selection { names[i] = e.Name() }
  return slurp_all1(dir, names) }

func slurp_all1(dir string, names []string) [][]byte {
  var (dirfs fs.FS; results [][]byte; i int; nm string; err error)
  dirfs = os.DirFS(dir)
  results = make([][]byte, len(names))
  for i, nm = range names {
    results[i], err = fs.ReadFile(dirfs, nm); assert_nil(err) }
  return results }

func _filter_prefix(dirents []os.DirEntry, prefix string) []os.DirEntry {
  var results []os.DirEntry; var e os.DirEntry
  results = make([]os.DirEntry, 0, len(dirents))
  for _, e = range dirents {
    if (strings.HasPrefix(e.Name(), prefix)) { results = append(results, e) } }
  return results }
