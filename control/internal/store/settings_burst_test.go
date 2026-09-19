package store

import "testing"

// A setting that is accepted, shown back, and then ignored by the engine is
// worse than one that is refused. The operator goes away believing a number
// that is not in force anywhere - and the number they believe is a protection
// figure, so they stop looking for the real one.
//
// MaxBurstSeconds mirrors MAX_DEBT in the Lua engine. These tests are what
// notices if the two drift apart.

func TestABurstTheEngineWouldIgnoreIsRefused(t *testing.T) {
	st := DefaultSettings()
	st.GlobalRateRPS = 5
	st.GlobalRateBurst = 10000 // over half an hour of debt at five a second

	if err := ValidateSettings(&st); err == nil {
		t.Fatal("a burst of 10000 at 5/s was accepted. The engine caps the debt " +
			"at 60 seconds, so only 300 of it is real - and the dashboard would " +
			"show 10000 back to the operator as if it were in force")
	}
}

func TestABurstAtTheCapIsAllowed(t *testing.T) {
	st := DefaultSettings()
	st.GlobalRateRPS = 20
	st.GlobalRateBurst = 20 * MaxBurstSeconds // exactly the most that can take effect

	if err := ValidateSettings(&st); err != nil {
		t.Fatalf("the largest burst that does take effect was refused: %v", err)
	}
}

func TestTheShippedDefaultsAreAcceptedByOurOwnValidation(t *testing.T) {
	// Sounds tautological and is not: the defaults and the validation are two
	// separate opinions about the same numbers, and one changing without the
	// other would ship a product that refuses its own settings on first save.
	st := DefaultSettings()
	if err := ValidateSettings(&st); err != nil {
		t.Fatalf("DefaultSettings does not pass ValidateSettings: %v", err)
	}
	if st.GlobalRateBurst > st.GlobalRateRPS*MaxBurstSeconds {
		t.Fatalf("the default burst %d cannot take effect at %d/s",
			st.GlobalRateBurst, st.GlobalRateRPS)
	}
}

func TestSwitchingTheLimitOffIsStillAllowed(t *testing.T) {
	// 0 means "no limit configured" everywhere else in the settings, so the
	// burst check must not turn clearing the field into an error.
	st := DefaultSettings()
	st.GlobalRateRPS = 0
	st.GlobalRateBurst = 5000

	if err := ValidateSettings(&st); err != nil {
		t.Fatalf("clearing the rate was refused because of the burst: %v", err)
	}
}
