package ratelimit

import "time"

type Rules struct {
	Global          Rule
	LoginIP         Rule
	LoginEmail      Rule
	RegisterIP      Rule
	ForgotIP        Rule
	ForgotEmail     Rule
	RefreshIP       Rule
	ResetIP         Rule
	VerifyIP        Rule
	ChangePasswdUID Rule
}

func DefaultRules() Rules {
	return Rules{
		Global:          Rule{Name: "global.ip", Limit: 100, Window: time.Minute},
		LoginIP:         Rule{Name: "login.ip", Limit: 5, Window: 15 * time.Minute},
		LoginEmail:      Rule{Name: "login.email", Limit: 5, Window: 15 * time.Minute},
		RegisterIP:      Rule{Name: "register.ip", Limit: 5, Window: time.Hour},
		ForgotIP:        Rule{Name: "forgot.ip", Limit: 3, Window: time.Hour},
		ForgotEmail:     Rule{Name: "forgot.email", Limit: 3, Window: time.Hour},
		RefreshIP:       Rule{Name: "refresh.ip", Limit: 30, Window: time.Hour},
		ResetIP:         Rule{Name: "reset.ip", Limit: 10, Window: time.Hour},
		VerifyIP:        Rule{Name: "verify.ip", Limit: 10, Window: time.Hour},
		ChangePasswdUID: Rule{Name: "change_password.user", Limit: 5, Window: time.Hour},
	}
}
