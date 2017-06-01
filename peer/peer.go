package peer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
)

/*
 * 1. Create a New Peer, which will
 *   ---generate a random public/private key
 *
 * 2.
 */

const (
	privateKeyBitLength = 2048

	sessionKeyByteLength = 64
)

var (
	sessionKeyLabel = []byte("session-key")
)

func generateSessionKey(random io.Reader) ([]byte, error) {
	if random == nil {
		// crypto/rand.Reader is a good source of entropy for randomizing the
		// encryption function if no other source of entropy is provided
		random = rand.Reader
	}

	sessionKey := make([]byte, sessionKeyByteLength)
	if _, err := io.ReadFull(random, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

type Peer struct {
	ID                  string
	rng                 io.Reader
	privateKey          *rsa.PrivateKey
	outgoingSessionKeys map[string]PeerConnection
	incomingSessionKeys map[string]PeerConnection
}

type PeerConnection struct {
	RemotePublicKey *rsa.PublicKey
	PlainSessionKey []byte
}

func New(random io.Reader) (*Peer, error) {
	if random == nil {
		// crypto/rand.Reader is a good source of entropy for randomizing the
		// encryption function if no other source of entropy is provided
		random = rand.Reader
	}
	p := Peer{
		rng:                 random,
		outgoingSessionKeys: make(map[string]PeerConnection),
		incomingSessionKeys: make(map[string]PeerConnection),
	}
	if err := p.generatePrivateKey(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Peer) generatePrivateKey() error {
	rng := rand.Reader

	privateKey, err := rsa.GenerateKey(rng, privateKeyBitLength)
	if err != nil {
		return err
	}

	p.privateKey = privateKey
	return nil
}

//GetPublicKey returns the PublicKey for the privateKey inside a peer
func (p *Peer) GetPublicKey() rsa.PublicKey {
	return p.privateKey.PublicKey
}

//GetOutgoingCipherSessionKey encrypts a session encryption key (in plaintext) to a cipher that the remote peer can decrypt
//for use by a remote peer
func (p *Peer) GetOutgoingCipherSessionKey(random io.Reader, destPublicKey rsa.PublicKey, destRemoteID string) ([]byte, error) {
	if destRemoteID == "" {
		return nil, errors.New("An identifier for the remote must be provided")
	}
	session, ok := p.outgoingSessionKeys[destRemoteID]
	if !ok {
		plainSessionKey, err := generateSessionKey(random)
		if err != nil {
			return nil, err
		}
		session = PeerConnection{&destPublicKey, plainSessionKey}
		p.outgoingSessionKeys[destRemoteID] = session
	}

	return rsa.EncryptOAEP(sha256.New(), p.rng, session.RemotePublicKey, session.PlainSessionKey, sessionKeyLabel)
}

//LoadIncomingCipherSessionKey decrypts a session encryption key (in ciphertext) to plaintext and stores it
func (p *Peer) LoadIncomingCipherSessionKey(cipherSessionKey []byte, sourcePublicKey rsa.PublicKey, sourceRemoteID string) error {
	if sourceRemoteID == "" {
		return errors.New("An identifier for the remote must be provided")
	}
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), p.rng, p.privateKey, cipherSessionKey, sessionKeyLabel)
	if err != nil {
		return err
	}
	p.incomingSessionKeys[sourceRemoteID] = PeerConnection{&sourcePublicKey, sessionKey}
	return nil
}
