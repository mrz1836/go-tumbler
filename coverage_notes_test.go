// This file documents the statements intentionally left uncovered by the test
// suite. Per the pragmatic coverage target we do NOT add production-only
// injection seams to reach defensive branches that valid inputs can never
// trigger. Each entry below was verified to be genuinely unreachable through
// any public API or existing test seam; together they account for the ~2% of
// core statements not covered (core is otherwise ~98%; transport ~99%;
// securebytes 100%).
//
// combine.go
//   - buildIKM   line ~86  (ikm.Use error): the IKM buffer is freshly
//     allocated by sbNewZero and used immediately; SecureBytes.Use only fails
//     on a destroyed buffer, which never happens before first use.
//   - deriveKEK  line ~141 (ikm.Use error): same freshly-allocated-IKM reason.
//   - hkdfSHA256ExtractExpand line ~103 (hkdf.Extract error) and deriveKEK
//     line ~134 (its wrapped error): stdlib crypto/hkdf Extract never errors
//     for SHA-256, and Expand only errors when the output length exceeds
//     255*HashSize (8160 B) — tumbler always requests 32 B.
//   - seal/open chacha20poly1305.New errors ARE covered (TestSeal_WrongKeySize /
//     TestOpen_WrongKeySize pass a non-32-byte key through the test seam).
//
// envelope.go
//   - Marshal line ~347 (envelope exceeds maxEnvelopeLen, 1 MiB): unreachable
//     because slot count is bounded to 64 and every field is length-bounded, so
//     the largest serializable envelope is only tens of KiB.
//   - reader.u8 line ~373 and parseSlot's six fixed-field reads (type, id,
//     flags, aead, kdfID, ykSlot): the slotFixedLen (13-byte) floor enforced
//     before the body reader is built guarantees those bytes are present, so
//     those short-read branches never fire. Variable-field short reads (u16,
//     hkdfSalt/nonce takes) ARE covered by TestParse_TruncatedSlotBody_EveryLength.
//
// yubikey.go
//   - unlock2FA line ~181 (deriveChallenge error): unlock always rebuilds a
//     real KDF via parseKDF, so the password key is a live SecureBytes;
//     deriveChallenge's only failure modes are a destroyed key (covered
//     directly via DeriveChallengeForTest and, for enroll, via a misbehaving
//     KDF) or an hkdf error (see below).
//   - deriveChallenge line ~210 (hkdf.Expand error): unreachable for the fixed
//     32-byte output, same as deriveKEK above.
//
// tumbler.go / method.go
//   - GenerateDEK's Use error and wrapDEK's seal error ARE covered
//     (TestGenerateDEK_UseError, TestWrapDEK_SealError_DestroyedDEK).

package tumbler_test
