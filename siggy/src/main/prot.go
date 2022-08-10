/* support for running a protocol (DKG, DSS) that can timeout */
package main; import "sync"

type Message struct { /* value object */
  RecipientIndex int
  RunId string
  Op int
  DTO any
}

/* Flaw: Francois points out that ID being random bits is inadequate.
         Attacker can replay somebody's messages from a past run. */
type protocol_run struct { /* entity */
  protocol int       /* 0=dkg, 1=dss */
  id string          /* globally unique id of a particular run */
  lck *sync.Mutex    /* protects the mutable (non-final) part of the struct */
  guest_index int    /* the guest this run is for */
  dat interface{}    /* DistKeyShare for DKG or equivalent for DSS */
  state int          /* op code of messages that we are presently accepting */
  steps map[int]func(*protocol_run)bool /* per state funcs, if any */
  buffer map[int][]Message /* per-op messages for processing in future state */
}
