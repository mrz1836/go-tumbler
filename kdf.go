package tumbler

import (
	"encoding/binary"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// pkLen is the length of a derived password key (pk). 32 bytes is ample: pk
// is HKDF input keying material, and the KDF's cost — not pk's length — is
// what resists offline password guessing.
const pkLen = 32

// defaultSaltLen is the salt length both built-in KDFs generate at enroll.
const defaultSaltLen = 16

// KDF-parameter safety bounds enforced by parseKDF BEFORE any derivation, so
// a tampered file cannot trigger a multi-gigabyte allocation. Legitimate
// parameters (hush: Argon2id m=256 MiB; sigil: scrypt logN=18) sit well
// inside these ceilings.
const (
	maxKDFMemBytes = 2 * 1024 * 1024 * 1024 // 2 GiB working-memory ceiling

	maxArgonTimeParam    = 32
	maxArgonThreadsParam = 16
	minArgonMemKiB       = 8

	minScryptLogN = 1
	maxScryptLogN = 22
	maxScryptR    = 32
	maxScryptP    = 16

	kdfParamsLenArgon2 = 9 // time(4) || memoryKiB(4) || threads(1)
	kdfParamsLenScrypt = 9 // logN(1) || r(4) || p(4)
)

// KDF is a pluggable password key-derivation function. Each app keeps its own
// parameters (hush: Argon2id; sigil: scrypt) and the ID plus serialized
// parameters are stored in — and authenticated by — every password slot, so
// the envelope is self-describing and re-derivable without app-side config.
type KDF interface {
	// ID reports the KDFID written into the slot.
	ID() KDFID
	// SaltLen is the salt length Derive expects (and enroll generates).
	SaltLen() int
	// MarshalParams serializes the cost parameters for storage in the slot.
	MarshalParams() []byte
	// Derive stretches password with salt into a fresh pkLen-byte key held in
	// a SecureBytes the caller must Destroy.
	Derive(password *securebytes.SecureBytes, salt []byte) (*securebytes.SecureBytes, error)
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

// Argon2idKDF implements KDF with Argon2id (RFC 9106).
type Argon2idKDF struct {
	time      uint32
	memoryKiB uint32
	threads   uint8
}

// NewArgon2idKDF constructs an Argon2id KDF. hush uses t=4, m=256*1024 KiB,
// p=4 to mirror internal/keys/derive.go.
func NewArgon2idKDF(time, memoryKiB uint32, threads uint8) *Argon2idKDF {
	return &Argon2idKDF{time: time, memoryKiB: memoryKiB, threads: threads}
}

// ID implements KDF.
func (k *Argon2idKDF) ID() KDFID { return KDFArgon2id }

// SaltLen implements KDF.
func (k *Argon2idKDF) SaltLen() int { return defaultSaltLen }

// MarshalParams implements KDF: time(4) || memoryKiB(4) || threads(1).
func (k *Argon2idKDF) MarshalParams() []byte {
	b := make([]byte, kdfParamsLenArgon2)
	binary.BigEndian.PutUint32(b[0:4], k.time)
	binary.BigEndian.PutUint32(b[4:8], k.memoryKiB)
	b[8] = k.threads
	return b
}

// Derive implements KDF.
func (k *Argon2idKDF) Derive(password *securebytes.SecureBytes, salt []byte) (*securebytes.SecureBytes, error) {
	var (
		out    *securebytes.SecureBytes
		outErr error
	)
	if useErr := password.Use(func(pw []byte) {
		raw := argon2.IDKey(pw, salt, k.time, k.memoryKiB, k.threads, pkLen)
		defer zero(raw)
		out, outErr = sbNew(raw)
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: argon2 password use: %w", useErr)
	}
	if outErr != nil {
		return nil, fmt.Errorf("tumbler: argon2 derive: %w", outErr)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// scrypt
// ---------------------------------------------------------------------------

// ScryptKDF implements KDF with scrypt (RFC 7914). N is stored as its log2
// so the power-of-two invariant is structural.
type ScryptKDF struct {
	logN uint8
	r    uint32
	p    uint32
}

// NewScryptKDF constructs a scrypt KDF from log2(N), r, and p. sigil uses
// logN=18 (age's secure default), r=8, p=1.
func NewScryptKDF(logN uint8, r, p uint32) *ScryptKDF {
	return &ScryptKDF{logN: logN, r: r, p: p}
}

// ID implements KDF.
func (k *ScryptKDF) ID() KDFID { return KDFScrypt }

// SaltLen implements KDF.
func (k *ScryptKDF) SaltLen() int { return defaultSaltLen }

// MarshalParams implements KDF: logN(1) || r(4) || p(4).
func (k *ScryptKDF) MarshalParams() []byte {
	b := make([]byte, kdfParamsLenScrypt)
	b[0] = k.logN
	binary.BigEndian.PutUint32(b[1:5], k.r)
	binary.BigEndian.PutUint32(b[5:9], k.p)
	return b
}

// Derive implements KDF.
func (k *ScryptKDF) Derive(password *securebytes.SecureBytes, salt []byte) (*securebytes.SecureBytes, error) {
	n := 1 << k.logN
	var (
		out    *securebytes.SecureBytes
		outErr error
	)
	if useErr := password.Use(func(pw []byte) {
		raw, e := scrypt.Key(pw, salt, n, int(k.r), int(k.p), pkLen)
		if e != nil {
			outErr = e
			return
		}
		defer zero(raw)
		out, outErr = sbNew(raw)
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: scrypt password use: %w", useErr)
	}
	if outErr != nil {
		return nil, fmt.Errorf("tumbler: scrypt derive: %w", outErr)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// parsing / bounds
// ---------------------------------------------------------------------------

// parseKDF reconstructs a KDF from a slot's stored KDFID and parameter bytes,
// enforcing safety bounds before returning. A KDFNone id returns (nil, nil):
// the caller (recovery method) applies no password stretch.
//
//nolint:gocognit,gocyclo // flat per-KDF validation switch; complexity is structural.
func parseKDF(id KDFID, params []byte) (KDF, error) {
	switch id {
	case KDFNone:
		if len(params) != 0 {
			return nil, fmt.Errorf("%w: none takes no params", ErrKDFParams)
		}
		return nil, nil //nolint:nilnil // KDFNone legitimately means 'no KDF applied' (recovery slots).

	case KDFArgon2id:
		if len(params) != kdfParamsLenArgon2 {
			return nil, fmt.Errorf("%w: argon2 params len %d", ErrKDFParams, len(params))
		}
		t := binary.BigEndian.Uint32(params[0:4])
		mem := binary.BigEndian.Uint32(params[4:8])
		threads := params[8]
		if t < 1 || t > maxArgonTimeParam {
			return nil, fmt.Errorf("%w: argon2 time %d", ErrKDFParams, t)
		}
		if mem < minArgonMemKiB || uint64(mem)*1024 > maxKDFMemBytes {
			return nil, fmt.Errorf("%w: argon2 memoryKiB %d", ErrKDFParams, mem)
		}
		if threads < 1 || threads > maxArgonThreadsParam {
			return nil, fmt.Errorf("%w: argon2 threads %d", ErrKDFParams, threads)
		}
		return NewArgon2idKDF(t, mem, threads), nil

	case KDFScrypt:
		if len(params) != kdfParamsLenScrypt {
			return nil, fmt.Errorf("%w: scrypt params len %d", ErrKDFParams, len(params))
		}
		logN := params[0]
		r := binary.BigEndian.Uint32(params[1:5])
		p := binary.BigEndian.Uint32(params[5:9])
		if logN < minScryptLogN || logN > maxScryptLogN {
			return nil, fmt.Errorf("%w: scrypt logN %d", ErrKDFParams, logN)
		}
		if r < 1 || r > maxScryptR {
			return nil, fmt.Errorf("%w: scrypt r %d", ErrKDFParams, r)
		}
		if p < 1 || p > maxScryptP {
			return nil, fmt.Errorf("%w: scrypt p %d", ErrKDFParams, p)
		}
		// scrypt working memory = 128 * N * r bytes; bound it (uint64, no overflow).
		if mem := uint64(128) * (uint64(1) << logN) * uint64(r); mem > maxKDFMemBytes {
			return nil, fmt.Errorf("%w: scrypt memory %d bytes", ErrKDFParams, mem)
		}
		return NewScryptKDF(logN, r, p), nil

	default:
		return nil, fmt.Errorf("%w: id %d", ErrUnsupportedKDF, id)
	}
}
