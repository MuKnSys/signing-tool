package main
import "go.dedis.ch/kyber/v3"

/* generates a keypair into temp files, printing their names */
func main() {
  var secret_key kyber.Scalar; var public_key kyber.Point
  secret_key = pick_secret(); public_key = compute_pub(secret_key)
  save_to_temp(secret_key, "secret_"); save_to_temp(public_key, "public_")
}
