/* A thread-safe, fast, large source of secure pseudo-random numbers */
/* Authoritative source: http://www.wispym.com/download/csprng.go */
/* Licence: This file may be used and redistributed as you wish. */
package csprng
import "sync"
import "crypto/rand"
import "crypto/cipher"
import "crypto/aes"

type csprng struct {
  rem int
  st cipher.Stream
  lck *sync.Mutex
}
const mebi int = 1048576
func renew(c *csprng) {
  var k []byte = make([]byte, 32)
  var err error
  _, err = rand.Read(k)
  if err != nil { panic(err) }
  var bc cipher.Block
  bc, err = aes.NewCipher(k)
  if err != nil { panic(err) }
  var iv0 []byte = make([]byte, 16)

  (*c).st = cipher.NewCTR(bc, iv0)
  (*c).rem = mebi
}
func min(x, y int) int { if x<y {return x} else {return y} }
func fill(r1 *csprng, dst []byte) {
  var dstlen int = len(dst)
  {var i int; for i = 0; i < dstlen; i = i + 1 {dst[i] = 0}}
  (*r1).lck.Lock(); defer (*r1).lck.Unlock()
  loop:
    if dstlen == 0 { return }
    if (*r1).rem == 0 { renew(r1) }
    {
      var n int = min(dstlen, (*r1).rem)
      var d []byte = dst[0:n]
      (*r1).st.XORKeyStream(d, d)
      (*r1).rem = (*r1).rem - n
      dst = dst[n:]
      dstlen = dstlen - n
    }
    goto loop
}

var rng *csprng = &csprng{rem: 0, lck: &sync.Mutex{}}

/* This is the easy, sensible interface */

func Fill(dst []byte) { fill(rng, dst) }

/* This is the peculiar Stream-inspired interface that kyber wants */

// not a cipher.Stream in Liskov's sense
type Rng interface { XORKeyStream(dst, src []byte) }
func Get() Rng { return Rng(rng) }
func (r *csprng) XORKeyStream(dst, src []byte) {
  var ls int = len(src)
  var ld int = len(dst)
  if ld < ls {panic("cipher.Stream specifies to panic at small dst")}
  if ld > ls {panic("Rng does not use src as you expect cipher.Stream to")}
  fill(r, dst[0:ls])
}
