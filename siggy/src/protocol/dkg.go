/* a plug-in for prot.go that implements the DKG protocol */
package main; import ("fmt"; "go.dedis.ch/kyber/v3/share/dkg/rabin")

type _dkg_prot_dat struct { qual []int } /* entity */

const (_op_init,_op_deal,_op_response,_op_justification,_op_vss_done,
       _op_commits,_op_compl_commits,_op_recons_commits,_op_dkg_final int =
       0,1,2,3,4,5,6,7,8)

func init() {
  register_protocol(
    protocol{
      code:           pc_dkg,
      make_kyber_dat: make_dkg_kdat,
      op_final:       _op_dkg_final,
      stages:
      []protocol_stage {
        ps(step_init,nil,nil,nil),
        ps(step_deal,process_deal,dto_to_deal,DealDTO{}),
        ps(nil,process_response,identity_unmarshaller,&dkg.Response{}),
        ps(nil,process_justification,dto_to_justification,JustificationDTO{}),
        ps(step_vss_done,nil,nil,nil),
        ps(step_commits,process_commits,dto_to_commits,CommitsDTO{}),
        ps(nil,process_compl_commits,dto_to_compl_commits,ComplCommitsDTO{}),
        ps(nil,process_recons_commits,dto_to_recons_commits,ReconsCommitsDTO{}),
        ps(step_final,nil,nil,nil) } })}

func make_dkg_kdat(g guest,members []member,threshold int) (any, error) {
  return dkg.NewDistKeyGenerator(suite, g.sec, member_pubs(members), threshold)}

func _dkg_kdat(run *protocol_run) *dkg.DistKeyGenerator {
  return (*run).kyber_dat.(*dkg.DistKeyGenerator) }

func _dkg_pdat(r *protocol_run) *_dkg_prot_dat {
  return (*r).prot_dat.(*_dkg_prot_dat) }

func _broadcast_qual[T,S any](run *protocol_run, op int, data T,
                              marshaller func(T)(S,error)) {
  var (dto any; e error)
  dto, e = marshaller(data)
  if e != nil {warn_prg(e); return}
  multicast((*_dkg_pdat(run)).qual, run, op, dto) }

func _cache_qual(r *protocol_run) { (*_dkg_pdat(r)).qual = _dkg_kdat(r).QUAL() }

func step_init(r *protocol_run) {(*r).prot_dat = &_dkg_prot_dat{qual: []int{}}}

func step_deal(run *protocol_run) {
  var (deals map[int]*dkg.Deal; d *dkg.Deal; idx int; err error; dto DealDTO)
  deals, err = _dkg_kdat(run).Deals()
  if err != nil {warn_prg(err); abandon(run); return}
  for idx, d = range deals {
    dto, err = deal_to_dto(d)
    if err != nil {warn_prg(err); continue}
    send(run, idx, _op_deal, dto) } }

func process_deal(run *protocol_run, deal any) {
  var (resp *dkg.Response; e error)
  resp, e = _dkg_kdat(run).ProcessDeal(deal.(*dkg.Deal))
  if e != nil { warn(e); return }
  if resp == nil { return } /* only for symmetry with other functions */
  broadcast(run, _op_response, resp) }

func process_response(run *protocol_run, resp any) {
  var (j *dkg.Justification; e error)
  j, e = _dkg_kdat(run).ProcessResponse(resp.(*dkg.Response))
  if e != nil { warn(e); return }
  if j == nil { return }
  var dto JustificationDTO
  dto, e = justification_to_dto(j)
  if e != nil { warn_prg(e); return }
  broadcast(run, _op_justification, dto) }

func process_justification(run *protocol_run, j any) {
  warn_if_err(_dkg_kdat(run).ProcessJustification(j.(*dkg.Justification))) }

func step_vss_done(run *protocol_run) {
  _dkg_kdat(run).SetTimeout()
  fmt.Println("guest/run/certified/qual: ",
              (*run).guest_index, (*run).id,
              _dkg_kdat(run).Certified(), len(_dkg_kdat(run).QUAL())) }

func step_commits(run *protocol_run) {
  var (sc *dkg.SecretCommits; e error)
  _cache_qual(run)
  abandon_if(run, !_dkg_kdat(run).Certified())
  if abandoned(run) { return }
  sc, e = _dkg_kdat(run).SecretCommits()
  if e != nil { warn_prg(e); abandon(run); return }
  _broadcast_qual(run, _op_commits, sc, commits_to_dto) }

func process_commits(run *protocol_run, commits any) {
  var (c *dkg.ComplaintCommits; e error)
  c, e = _dkg_kdat(run).ProcessSecretCommits(commits.(*dkg.SecretCommits))
  if e != nil { warn(e); return }
  if c == nil { return }
  _broadcast_qual(run, _op_compl_commits, c, compl_commits_to_dto) }

func process_compl_commits(run *protocol_run, compl any) {
  var (r *dkg.ReconstructCommits; e error)
  r, e = _dkg_kdat(run).ProcessComplaintCommits(compl.(*dkg.ComplaintCommits))
  if e != nil { warn(e); return }
  if r == nil { return }
  _broadcast_qual(run, _op_recons_commits, r, recons_commits_to_dto) }

func process_recons_commits(run *protocol_run, recons any) {
  warn_if_err(
    _dkg_kdat(run).ProcessReconstructCommits(recons.(*dkg.ReconstructCommits)))}

//TODO delete completed protocol runs once we've no more use for them
func step_final(run *protocol_run) {
  var (share *dkg.DistKeyShare; e error)
  if _dkg_kdat(run).Finished() {
    share, e = _dkg_kdat(run).DistKeyShare()
    if e != nil { warn(e); return }
    fmt.Println("DistKeyShare: ", share)
  } else {
    fmt.Println("finished is false")
  } }
