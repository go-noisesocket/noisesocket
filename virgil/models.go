package virgil

type AuthInfo struct {
	Identity  string `json:"identity"`
	Signature []byte `json:"signature"`
}
