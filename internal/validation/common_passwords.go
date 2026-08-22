package validation

import "strings"

var commonPasswordList = []string{
	"123456", "123456789", "12345678", "password", "qwerty", "abc123",
	"111111", "123123", "1234567890", "1234567", "qwerty123", "000000",
	"1q2w3e", "aa12345678", "abc123456", "password1", "1234", "qwertyuiop",
	"123321", "password123", "1q2w3e4r5t", "iloveyou", "monkey", "dragon",
	"sunshine", "princess", "football", "charlie", "aa123456", "donald",
	"letmein", "zaq12wsx", "welcome", "login", "admin", "passw0rd",
	"master", "hello", "freedom", "whatever", "trustno1", "starwars",
	"qazwsxedc", "michael", "shadow", "superman", "batman", "jordan23",
	"asdfghjkl", "zxcvbnm", "qwerty1234", "test1234", "computer", "internet",
	"samsung", "google", "iloveyou1", "myspace1", "baseball", "soccer",
	"jennifer", "jessica", "michelle", "hunter2", "thomas", "harley",
	"ranger", "buster", "tigger", "purple", "silver", "orange",
	"secret", "summer", "winter", "autumn", "spring", "password12",
	"passwordpassword", "administrator", "letmein123", "iloveyou123",
	"welcome123", "welcome1234", "changeme", "changeme123", "default",
	"newpassword", "temppassword", "temporary", "guest", "root",
	"toor", "pass1234", "pass12345", "123qweasdzxc", "1qaz2wsx3edc",
	"qwerty12345", "asdfghjkl123", "loveme123", "sunshine123", "princess123",
	"football123", "baseball123", "starwars123", "superman123", "batman123",
	"dragon123", "monkey123", "shadow123", "master123", "freedom123",
	"whatever123", "trustno1234", "michael123", "jennifer123", "jessica123",
	"corporate1", "company123", "business123", "office123", "windows123",
	"linux1234", "database123", "server123", "network123", "system123",
	"security123", "manager123", "developer123", "engineer123", "student123",
	"teacher123", "school123", "college123", "university123", "hospital123",
	"doctor123", "nurse123", "police123", "soldier123", "captain123",
	"december2023", "january2024", "summer2023", "summer2024", "winter2023",
	"winter2024", "spring2024", "autumn2024", "password2023", "password2024",
	"qwertyuiop123", "1234qwerasdf", "asdf1234asdf", "zxcv1234zxcv",
	"abcd1234abcd", "abcdefghijkl", "123456789012", "111111111111",
	"000000000000", "aaaaaaaaaaaa", "qwertyqwerty", "abcabcabcabc",
	"letmein1234", "openseasame", "opensesame123", "iloveyouforever",
	"ihatethis123", "nopassword12", "mypassword12", "thisisapassword",
	"correcthorsebatterystaple", "adminadmin12", "rootroot1234",
	"welcometothejungle", "keyboardcat1", "sunshinerainbow", "trustnoone123",
}

var commonPasswords = func() map[string]struct{} {
	m := make(map[string]struct{}, len(commonPasswordList))
	for _, p := range commonPasswordList {
		m[p] = struct{}{}
	}
	return m
}()

func IsCommonPassword(password string) bool {
	_, ok := commonPasswords[strings.ToLower(strings.TrimSpace(password))]
	return ok
}
