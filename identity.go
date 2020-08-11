package ginOidc

// This is juste an exemple, define groups as it is named in Keycloak.
// Here the groupe "operator" is a subgroup of group "agritracking"
const operator = "/agritracking/operator"
const supervisor = "/agritracking/supervisor"
const administrator = "/agritracking/administrator"
const customer = "/agritracking/customer"
const archivist = "/agritracking/archivist"

// Identity struct can be customize with all the field you need.
// If a field is not present in the token, you have to setup Keycloak mapper to inject them.
// In Keycloak :
// -> Clients -> you client -> Mappers -> "Create" or "Add Builtin" (depending of what your need)
// For exemple to add group membership
// -> "Create" ->
// 		Name : group_membership,
// 		Mapper type : Group Membership,
//		Token Claim Name : group_membership,
// 		Full group path : "On"
//		Add to ID Token : "On",
//		Add to access token : "On",
//		Add to userinfo : "On"
// Then just map the `json:` tag of struct field to "Token Claim Name" you've defined.
type Identity struct {
	Id        string   `json:"sub" pg:",pk,notnull,unique"`
	FirstName string   `json:"given_name"`
	LastName  string   `json:"family_name"`
	FullName  string   `json:"name"`
	Email     string   `json:"email"`
	Groups    []string `json:"group_membership"`
}

func (i Identity) IsOperator() bool {
	return contain(i.Groups, operator)
}

func (i Identity) IsSupervisor() bool {
	return contain(i.Groups, supervisor)
}

func (i Identity) IsAdministrator() bool {
	return contain(i.Groups, administrator)
}

func (i Identity) IsCustomer() bool {
	return contain(i.Groups, customer)
}

func (i Identity) IsArchivist() bool {
	return contain(i.Groups, archivist)
}

// A user can be member of many groups, then we have to test if the group name we need is in the list.
func contain(proposal []string, lookingFor string) bool {
	for _, s := range proposal {
		if s == lookingFor {
			return true
		}
	}
	return false
}
