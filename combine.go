package tumbler

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
	"golang.org/x/crypto/chacha20poly1305"
)

// Domain-separation labels. Every one is prefixed "tumbler/v1 " so a future
// format version derives structurally distinct keys from identical inputs.
const (
	labelIKM       = "tumbler/v1 ikm"
	labelKEK       = "tumbler/v1 kek"
	labelChallenge = "tumbler/v1 challenge"
)

// ikmInputs carries the (optionally absent) secret factors that feed the
// input keying material for a slot's KEK. Exactly which are present is
// determined by the slot's method type:
//
//	MethodPassword           -> password only
//	MethodYubiKey            -> yubiResp only
//	MethodPasswordAndYubiKey -> password AND yubiResp
//	MethodRecovery           -> recovery only
//
// The three roles are always encoded in a fixed order with explicit
// presence markers and length prefixes, so no two distinct configurations
// can ever produce the same IKM byte string (even if two secrets collide).
type ikmInputs struct {
	password *securebytes.SecureBytes // pk = KDF(password, salt)
	yubiResp *securebytes.SecureBytes // yr = HMAC-SHA1(yk_secret, challenge)
	recovery *securebytes.SecureBytes // rc = the raw recovery code
}

// buildIKM assembles the length-prefixed, role-tagged input keying material
// into a fresh SecureBytes the caller must Destroy.
//
// Layout:
//
//	labelIKM
//	presence(1) len(2) password   (len=0, no bytes, when absent)
//	presence(1) len(2) yubiResp
//	presence(1) len(2) recovery
func buildIKM(in ikmInputs) (*securebytes.SecureBytes, error) {
	roles := []*securebytes.SecureBytes{in.password, in.yubiResp, in.recovery}

	size := len(labelIKM)
	for _, r := range roles {
		size += 1 + 2 // presence + length
		if r != nil {
			size += r.Len()
		}
	}

	ikm, err := sbNewZero(size)
	if err != nil {
		return nil, fmt.Errorf("tumbler: allocate ikm: %w", err)
	}

	var fillErr error
	if useErr := ikm.Use(func(dst []byte) {
		n := copy(dst, labelIKM)
		for _, r := range roles {
			if r == nil {
				dst[n] = 0
				n++
				binary.BigEndian.PutUint16(dst[n:], 0)
				n += 2
				continue
			}
			dst[n] = 1
			n++
			if e := r.Use(func(s []byte) {
				binary.BigEndian.PutUint16(dst[n:], uint16(len(s))) //nolint:gosec // G115: role secrets are <=64 bytes, well under uint16
				n += 2
				n += copy(dst[n:], s)
			}); e != nil {
				fillErr = e
				return
			}
		}
	}); useErr != nil {
		_ = ikm.Destroy()
		return nil, fmt.Errorf("tumbler: fill ikm: %w", useErr)
	}
	if fillErr != nil {
		_ = ikm.Destroy()
		return nil, fmt.Errorf("tumbler: fill ikm role: %w", fillErr)
	}
	return ikm, nil
}

// deriveKEK combines the IKM into a 32-byte key-encryption key using
// HKDF-SHA256: PRK = Extract(hkdfSalt, IKM); KEK = Expand(PRK, info), where
// info = labelKEK || version || methodType || slotID. The KEK is returned in
// a SecureBytes the caller must Destroy. The transient PRK and raw KEK
// buffers produced by the stdlib HKDF (which are not mlocked) are zeroed
// before return.
func deriveKEK(in ikmInputs, hkdfSalt []byte, version uint8, mt MethodType, slotID [8]byte) (*securebytes.SecureBytes, error) {
	ikm, err := buildIKM(in)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ikm.Destroy() }()

	info := make([]byte, 0, len(labelKEK)+1+1+8)
	info = append(info, labelKEK...)
	info = append(info, version, byte(mt))
	info = append(info, slotID[:]...)

	var (
		kek    *securebytes.SecureBytes
		kekErr error
	)
	if useErr := ikm.Use(func(ikmBytes []byte) {
		prk, e := hkdf.Extract(sha256.New, ikmBytes, hkdfSalt)
		if e != nil {
			kekErr = e
			return
		}
		defer zero(prk)

		raw, e := hkdf.Expand(sha256.New, prk, string(info), chacha20poly1305.KeySize)
		if e != nil {
			kekErr = e
			return
		}
		defer zero(raw)

		kek, kekErr = sbNew(raw) // New copies raw then zeroes it.
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: kek ikm use: %w", useErr)
	}
	if kekErr != nil {
		return nil, fmt.Errorf("tumbler: derive kek: %w", kekErr)
	}
	return kek, nil
}

// seal wraps the data key with ChaCha20-Poly1305 under kek, binding aad
// (the slot metadata) into the tag. The 32-byte key and the plaintext DEK
// are borrowed only for the duration of the seal. Returns ciphertext||tag.
func seal(kek, dek *securebytes.SecureBytes, nonce, aad []byte) ([]byte, error) {
	var (
		out     []byte
		sealErr error
	)
	if useErr := kek.Use(func(key []byte) {
		aead, e := chacha20poly1305.New(key)
		if e != nil {
			sealErr = e
			return
		}
		sealErr = dek.Use(func(pt []byte) {
			out = aead.Seal(nil, nonce, pt, aad)
		})
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: seal kek use: %w", useErr)
	}
	if sealErr != nil {
		return nil, fmt.Errorf("tumbler: seal: %w", sealErr)
	}
	return out, nil
}

// open unwraps ciphertext with ChaCha20-Poly1305 under kek, verifying aad.
// A verification failure (wrong key, tampered slot, bad tag) returns
// ErrAuthFailed with no further detail. On success the recovered data key is
// copied into a fresh SecureBytes the caller owns; the transient plaintext
// returned by the AEAD is zeroed before return.
func open(kek *securebytes.SecureBytes, nonce, ciphertext, aad []byte) (*securebytes.SecureBytes, error) {
	var (
		dek     *securebytes.SecureBytes
		authErr bool
		openErr error
	)
	if useErr := kek.Use(func(key []byte) {
		aead, e := chacha20poly1305.New(key)
		if e != nil {
			openErr = e
			return
		}
		pt, e := aead.Open(nil, nonce, ciphertext, aad)
		if e != nil {
			authErr = true
			return
		}
		defer zero(pt)
		dek, openErr = sbNew(pt) // New copies pt then zeroes it.
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: open kek use: %w", useErr)
	}
	if authErr {
		return nil, ErrAuthFailed
	}
	if openErr != nil {
		return nil, fmt.Errorf("tumbler: open: %w", openErr)
	}
	return dek, nil
}

// zero overwrites every byte of b with 0. Kept as a tiny standalone helper so
// the loop survives compiler changes for slices reachable through a defer.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
