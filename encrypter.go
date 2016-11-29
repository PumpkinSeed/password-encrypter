package encrypter

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"math/rand"
	"strconv"
	"time"
)

// Encrypter is the config
type Encrypter struct {
	Iteration  int
	SaltLength int
}

// New create a new Encrypter instance
func New(c interface{}) {
	var encrypter = Encrypter{
		Iteration:  5000,
		SaltLength: 32,
	}

	for k, v := range c {
		if k == "iteration" {
			encrypter.Iteration = strconv.Atoi(v)
		}
		if k == "saltLength" {
			encrypter.SaltLength = strconv.Atoi(v)
		}
	}

	return encrypter
}

// VerifyPassword compares password and the hashed password
func (e *Encrypter) VerifyPassword(passwordHash, password, salt string) error {
	return compareHashAndPassword([]byte(passwordHash), password, []byte(salt))

}

// HashPassword creates the own password hash
func (e *Encrypter) HashPassword(password string) ([]byte, []byte, error) {
	return ownEncryption(password, false, []byte(""))
}

func (e *Encrypter) ownEncryption(password string, isSalted bool, salt []byte) ([]byte, []byte, error) {
	var (
		hasher    hash.Hash
		container []byte
		key       []byte
	)

	if isSalted {
		key = []byte(password + "{" + string(salt) + "}")
	} else {
		salt = saltGenerator(e.SaltLength)
		key = []byte(password + "{" + string(salt) + "}")
	}

	hasher = sha512.New()
	hasher.Write(key)
	container = hasher.Sum(nil)

	for i := 1; i < e.Iteration; i++ {
		new := append(container[:], key[:]...)

		hasher = sha512.New()
		hasher.Write(new)
		container = hasher.Sum(nil)
	}
	digest := []byte(base64.StdEncoding.EncodeToString(container))

	return digest, salt, nil
}

func (e *Encrypter) saltGenerator(len int) []byte {
	rand.Seed(int64(time.Now().Nanosecond()))
	random := rand.Intn(10000000)
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(random)))
	code := h.Sum(nil)
	codestr := hex.EncodeToString(code)
	return []byte(codestr[:len])
}

func (e *Encrypter) compareHashAndPassword(hash []byte, plain string, salt []byte) error {
	digest, _, err := ownEncryption(plain, true, salt)
	if err != nil {
		return err
	}
	compare := subtle.ConstantTimeCompare(hash, digest)
	if compare == 1 {
		return nil
	}
	return errors.New("The password is not correct")
}
