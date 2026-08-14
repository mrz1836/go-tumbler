package tumbler

import "fmt"

// SafetyReport is the result of the safe-default validator: a list of
// non-fatal warnings the caller should surface to the user. A fatal condition
// is reported via the error return of ValidateSafety, not here.
type SafetyReport struct {
	// Warnings are human-readable advisories (e.g. "no recovery code enrolled").
	Warnings []string
	// UnlockSlots is the total number of slots that can open the envelope.
	UnlockSlots int
	// HasRecovery reports whether at least one recovery slot is enrolled.
	HasRecovery bool
}

// ValidateSafety assesses an envelope against safe-default rules and returns
// advisory warnings plus a fatal error for dangerous configurations.
//
// Hard-unsafe (returns ErrPolicyUnsafe unless force is true):
//   - a single-slot YubiKey-only envelope. The CR path has no PIN, so a
//     stolen key plus the stolen file is enough to unlock, and with no second
//     slot a lost key means permanent lockout.
//
// Soft warnings (never fatal):
//   - fewer than two unlock slots (no backup key / recovery code);
//   - no recovery slot enrolled;
//   - YubiKey-only posture (presence, not identity).
func (e *Envelope) ValidateSafety(force bool) (*SafetyReport, error) {
	rep := &SafetyReport{UnlockSlots: len(e.slots)}
	for i := range e.slots {
		if e.slots[i].Type == MethodRecovery {
			rep.HasRecovery = true
		}
	}

	eff := e.EffectivePolicy()

	if eff == PolicyYubiKeyOnly && rep.UnlockSlots == 1 && !force {
		return rep, fmt.Errorf("%w: single-slot yubikey-only (no PIN, no backup); "+
			"add a backup key or recovery code, or pass force", ErrPolicyUnsafe)
	}

	if eff == PolicyYubiKeyOnly {
		rep.Warnings = append(rep.Warnings,
			"yubikey-only proves presence, not identity: a stolen key + file can unlock; prefer password-and-yubikey")
	}
	if rep.UnlockSlots < 2 {
		rep.Warnings = append(rep.Warnings,
			"only one unlock method enrolled: a lost factor means permanent lockout; enroll a backup key or recovery code")
	}
	if !rep.HasRecovery {
		rep.Warnings = append(rep.Warnings,
			"no recovery code enrolled: consider `recovery-code` as an offline escape hatch")
	}
	return rep, nil
}
