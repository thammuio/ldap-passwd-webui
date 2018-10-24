package app

import (
	"crypto/tls"
	"fmt"
	"log"


	"gopkg.in/ldap.v2"
	"golang.org/x/text/encoding/unicode"
)

// SecurityProtocol protocol type
type SecurityProtocol int

// Note: new type must be added at the end of list to maintain compatibility.
const (
	SecurityProtocolUnencrypted SecurityProtocol = iota
	SecurityProtocolLDAPS
	SecurityProtocolStartTLS
)

// LDAPClient Basic LDAP authentication service
type LDAPClient struct {
	Name             string // canonical name (ie. corporate.ad)
	Host             string // LDAP host
	Port             int    // port number
	LDAPType 		 string // AD or LDAP
	SecurityProtocol SecurityProtocol
	SkipVerify       bool
	BindDN           string // Template for the Bind DN
	BindDNpass       string // Template for the Bind DN PAssword
	UserSearchFilter string // User Search Filter
	UserBase         string // Base search path for users
	UserDN           string // Template for the DN of the user for simple auth
	Enabled          bool   // if this LDAPClient is disabled
}

func bindUserDN(l *ldap.Conn, bindDN, bindDNpass string) error {
	log.Printf("\nBinding with bindDN: %s", bindDN)
	err := l.Bind(bindDN, bindDNpass)
	if err != nil {
		log.Printf("\nLDAP auth. failed for %s, reason: %v", bindDN, err)
		return err
	}
	log.Printf("\nBound successfully with bindDN: %s", bindDN)
	return err
}

func (ls *LDAPClient) bindDN(l *ldap.Conn) error {
	log.Printf("\nBinding with bindDN: %s", ls.BindDN)
	err := l.Bind(ls.BindDN, ls.BindDNpass)
	if err != nil {
		log.Printf("\nLDAP auth. failed for %s, reason: %v", ls.BindDN, err)
		return err
	}
	log.Printf("\nBound successfully with bindDN: %s", ls.BindDN)
	return err
}


func (ls *LDAPClient) bindUserDNAgain(l *ldap.Conn, newUserDN, passwd string) error {
	log.Printf("\nBinding with userDN: %s", newUserDN)
	log.Printf("\nBinding with userDN passwd: %s", passwd)
	err := l.Bind(newUserDN, passwd)
	if err != nil {
		log.Printf("\nLDAP auth. failed for %s, reason: %v", newUserDN, err)
		return err
	}
	log.Printf("\nBound successfully with bindDN: %s", newUserDN)
	return err
}

// func (ls *LDAPClient) sanitizedFilter(filter) (string, bool) {
// 	// See http://tools.ietf.org/search/rfc4514: "special characters"
// 	badCharacters := "\x00()*\\,='\"#+;<>"
// 	if strings.ContainsAny(filter, badCharacters) {
// 		log.Printf("\n'%s' contains invalid DN characters. Aborting.", filter)
// 		return "", false
// 	}

// 	return fmt.Sprintf(ls.UserSearchFilter, filter), true
// }

// func (ls *LDAPClient) sanitizedUserDN(username) (string, bool) {
// 	// See http://tools.ietf.org/search/rfc4514: "special characters"
// 	badCharacters := "\x00()*\\,='\"#+;<>"
// 	if strings.ContainsAny(username, badCharacters) {
// 		log.Printf("\n'%s' contains invalid DN characters. Aborting.", username)
// 		return "", false
// 	}

// 	return fmt.Sprintf(ls.UserDN, username), true
// }

// func (ls *LDAPClient) sanitizedBindDN(username) (string, bool) {
// 	// See http://tools.ietf.org/search/rfc4514: "special characters"
// 	badCharacters := "\x00()*\\,='\"#+;<>"
// 	if strings.ContainsAny(username, badCharacters) {
// 		log.Printf("\n'%s' contains invalid DN characters. Aborting.", username)
// 		return "", false
// 	}

// 	return fmt.Sprintf(ls.BindDN, username), true
// }


func dial(ls *LDAPClient) (*ldap.Conn, error) {
	log.Printf("\nDialing LDAP with security protocol (%v) without verifying: %v", ls.SecurityProtocol, ls.SkipVerify)

	tlsCfg := &tls.Config{
		ServerName:         ls.Host,
		InsecureSkipVerify: ls.SkipVerify,
	}
	if ls.SecurityProtocol == SecurityProtocolLDAPS {
		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port), tlsCfg)
	}

	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port))
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}

	if ls.SecurityProtocol == SecurityProtocolStartTLS {
		if err = conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}

	return conn, nil
}

// ModifyPassword : modify user's password
func (ls *LDAPClient) ModifyPassword(name, passwd, newPassword string) error {
	// Printing all variables
	log.Printf("\n ====================================")
	log.Printf("\n Host: %s", ls.Host)
	log.Printf("\nPort: %s", ls.Port)
	log.Printf("\nSecurityProtocol: %s", ls.SecurityProtocol)
	log.Printf("\nSkipVerify: %s", ls.SkipVerify)
	log.Printf("\nBindDNpass: %s", ls.BindDNpass)
	log.Printf("\nBindDN: %s", ls.BindDN)
	log.Printf("\nUserSearchFilter: %s", ls.UserSearchFilter)
	log.Printf("\nUserDN %s", ls.UserDN)
	log.Printf("\nUserBase %s", ls.UserBase)
	log.Printf("\n ====================================")


	if len(passwd) == 0 {
		return fmt.Errorf("Auth. failed for %s, password cannot be empty", name)
	}
	l, err := dial(ls)
	if err != nil {
		ls.Enabled = false
		return fmt.Errorf("LDAP Connect error, %s:%v", ls.Host, err)
	}
	defer l.Close()

	// var userDN string
	log.Printf("\nLDAP will bind directly via BindDN template: %s", ls.BindDN)

	// var ok bool

	//BindDN, ok = ls.sanitizedUserDN(ls.BindDN)
	// if !ok {
	// 	return fmt.Errorf("Error sanitizing name %s", ls.BindDN)
	// }

	// bind with BindUSerDN to get user DN
	ls.bindDN(l)

	var newUserSearchFilter string
	// newUserSearchFilter, ok = ls.sanitizedFilter(ls.UserSearchFilter)
	log.Printf("\nnewUserSearchFilter is: %s", newUserSearchFilter)

	// Search for the given username to get DN
	// searchRequest := ldap.NewSearchRequest(
	// 	ls.UserBase, // The base dn to search
	// 	ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
	// 	// newUserSearchFilter, // The filter to apply
	// 	fmt.Sprintf(ls.UserSearchFilter, name),
	// 	[]string{"dn"}, // A list attributes to retrieve
	// 	nil,
	// )
	searchRequest := ldap.NewSearchRequest(ls.UserBase, 2, 0, 0, 0, false, fmt.Sprintf(ls.UserSearchFilter, name), []string{"dn"}, nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}
	
	newUserDN := sr.Entries[0].DN
	log.Printf("\n searched newUserDN: %s", newUserDN)

	// SearchtoGetUserDN(name)
	// bindUser(l, BindDN, BindDNpass)

    // Bind as the user to verify their password - don't need to bind again
	// bindUserDN(l, newUserDN, passwd)




	log.Printf("\nLDAP will execute password change on: %s", newUserDN)


	// flow based on AD/LDAP
	if ls.LDAPType == AD {
		
	ls.bindUserDNAgain(l, newUserDN, passwd)

    utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	// According to the MS docs in the links above https://github.com/go-ldap/ldap/issues/106
	// The password needs to be enclosed in quotes
	// pwdEncoded, _ := utf16.NewEncoder().String("\"testpassword\"")

	newPasswordEncoded, _ := utf16.NewEncoder().String(newPassword)

	log.Printf("\nEncoded newPassword : %s", newPasswordEncoded)

	passReq := &ldap.ModifyRequest{
	DN: newUserDN, // DN for the user we're resetting
	ReplaceAttributes: []ldap.PartialAttribute{
		{"unicodePwd", []string{newPasswordEncoded}},
	},
	}
	_, err = l.Modify(passReq)

	if err != nil {
		log.Printf("\n Not able to Change Password for user %s, reason: %v", newUserDN, err)
	}
	return err

	} else {

	ls.bindUserDNAgain(l, newUserDN, passwd)

	req := ldap.NewPasswordModifyRequest(newUserDN, passwd, newPassword)
	_, err = l.PasswordModify(req)

	if err != nil {
		log.Printf("\n Not able to Change Password for user %s, reason: %v", newUserDN, err)
	}
	return err


	}
	


}

// // Serch with sAMAccountName to get the UserDN -- Might not needed this
// func (ls *LDAPClient) SearchtoGetUserDN(name) {
	
// 	if len(BindDNpass) == 0 {
// 		return fmt.Errorf("Auth. failed for %s, password cannot be empty", BindDN)
// 	}
// 	l, err := dial(ls)
// 	if err != nil {
// 		ls.Enabled = false
// 		return fmt.Errorf("LDAP Connect error, %s:%v", ls.Host, err)
// 	}
// 	defer l.Close()
// 	bindUser(l, BindDN, BindDNpass)


// 	searchRequest := NewSearchRequest(
// 		UserBase, // The base dn to search
// 		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
// 		UserSearchFilter, // The filter to apply
// 		[]string{"dn", "cn"},                    // A list attributes to retrieve
// 		nil,
// 	)

// 	sr, err := l.Search(searchRequest)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	for _, entry := range sr.Entries {
// 		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
// 	}
// }


// NewLDAPClient : Creates new LDAPClient capable of binding and changing passwords
func NewLDAPClient() *LDAPClient {

	securityProtocol := SecurityProtocolUnencrypted
	if envBool("LPW_ENCRYPTED", true) {
		securityProtocol = SecurityProtocolLDAPS
		if envBool("LPW_START_TLS", false) {
			securityProtocol = SecurityProtocolStartTLS
		}
	}

	return &LDAPClient{
		Host:             envStr("LPW_HOST", ""),
		Port:             envInt("LPW_PORT", 636), // 389
		LDAPType:         envStr("LPW_TYPE", ""),
		SecurityProtocol: securityProtocol,
		SkipVerify:       envBool("LPW_SSL_SKIP_VERIFY", false),
		BindDN:           envStr("LPW_BIND_DN", ""),
		BindDNpass:       envStr("LPW_BIND_DN_PASS", ""),
		UserSearchFilter: envStr("LPW_USER_SEARCH_FILTER", "sAMAccountName=%s"),
		UserDN:           envStr("LPW_USER_DN", "uid=%s,ou=people,dc=example,dc=org"),
		UserBase:         envStr("LPW_USER_BASE", "ou=people,dc=example,dc=org"),
	}
}
