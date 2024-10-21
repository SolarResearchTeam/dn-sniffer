package datastructures

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Users struct {
	Id                     primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Username               string             `bson:"username"`
	FirstName              string             `bson:"first_name"`
	LastName               string             `bson:"last_name"`
	Email                  string             `bson:"email"`
	Password               string             `bson:"password"`
	IsLocked               bool               `bson:"islocked"`
	PasswordChangeRequired bool               `bson:"change_password"`
	Role                   string             `bson:"role"`
	Rights                 map[string]bool    `bson:"rights"`
	RestoreToken           string             `bson:"restoretoken"`
	RestoreTokenDate       string             `bson:"restoretokendate"`
}

// Roles Defaults
var RightsAnonymous = map[string]bool{
	"account_view": false,

	//Users
	"users_list":  false,
	"user_create": false,
	"user_view":   false,
	"user_edit":   false,
	"user_delete": false,

	//Zones
	"zones_view":  false,
	"zone_view":   false,
	"zones_edit":  false,
	"zone_create": false,
	"zone_edit":   false,
	"zone_delete": false,
	"zone_clean":  false,

	//Rebind
	"rebind_view":   false,
	"rebind_create": false,
	"rebind_edit":   false,
	"rebind_delete": false,

	//Blackhole
	"blackhole_view":   false,
	"blackhole_create": false,
	"blackhole_edit":   false,
	"blackhole_delete": false,
	"blackhole_clean":  false,

	//DNS records
	"records_view":  false,
	"record_create": false,
	"record_edit":   false,
	"record_delete": false,

	//Interacts
	"interacts_view":       false,
	"interacts_share":      false,
	"interact_edit_config": false,
	"interact_view":        false,
	"interact_create":      false,
	"interact_edit":        false,
	"interact_delete":      false,
	"interact_clean":       false,
	"interact_run":         false,

	//XSS hunter
	"xsshunters_view":          false,
	"xsshunter_view":           false,
	"xsshunter_payload_view":   false,
	"xsshunter_create":         false,
	"xsshunter_edit":           false,
	"xsshunter_delete":         false,
	"xsshunter_clean":          false,
	"xsshunter_payload_create": false,

	//Logs
	"logs": false,
	//SSL certs
	"certs": false,
}

var RightsUser = map[string]bool{
	"account_view": true,

	//Users
	"users_list":  false,
	"user_create": false,
	"user_view":   false,
	"user_edit":   false,
	"user_delete": false,

	//Zones
	"zones_view": true,
	"zones_edit": false,

	"zone_view":   true,
	"zone_create": false,
	"zone_edit":   false,
	"zone_delete": false,
	"zone_clean":  false,

	//Rebind
	"rebind_view":   true,
	"rebind_create": true,
	"rebind_edit":   true,
	"rebind_delete": true,

	//Blackhole
	"blackhole_view":   true,
	"blackhole_create": true,
	"blackhole_edit":   true,
	"blackhole_delete": true,
	"blackhole_clean":  false,

	//DNS records
	"records_view":  true,
	"record_create": true,
	"record_edit":   true,
	"record_delete": true,

	//Interacts
	"interacts_view":  true,
	"interacts_share": true,
	"interact_edit_config":  false,
	"interact_view":   true,
	"interact_create": true,
	"interact_edit":   true,
	"interact_delete": false,
	"interact_clean":  false,
	"interact_run":    true,

	//XSS hunter
	"xsshunters_view":          true,
	"xsshunter_view":           true,
	"xsshunter_payload_view":   true,
	"xsshunter_payload_create": true,
	"xsshunter_create":         false,
	"xsshunter_edit":           false,
	"xsshunter_delete":         false,
	"xsshunter_clean":          false,

	//Logs
	"logs": false,
	//SSL certs
	"certs": false,
}

var RightsAdmin = map[string]bool{
	"account_view": true,

	//Users
	"users_list":  true,
	"user_create": true,
	"user_view":   true,
	"user_edit":   true,
	"user_delete": true,

	//Zones
	"zones_view":  true,
	"zones_edit":  true,
	"zone_view":   true,
	"zone_create": true,
	"zone_edit":   true,
	"zone_delete": true,
	"zone_clean":  true,

	//Rebind
	"rebind_view":   true,
	"rebind_create": true,
	"rebind_edit":   true,
	"rebind_delete": true,

	//Blackhole
	"blackhole_view":   true,
	"blackhole_create": true,
	"blackhole_edit":   true,
	"blackhole_delete": true,
	"blackhole_clean":  true,

	//DNS records
	"records_view":  true,
	"record_create": true,
	"record_edit":   true,
	"record_delete": true,

	//Interacts
	"interacts_view":  true,
	"interacts_share": true,
	"interact_edit_config":  true,
	"interact_view":   true,
	"interact_create": true,
	"interact_edit":   true,
	"interact_delete": true,
	"interact_clean":  true,
	"interact_run":    true,

	//XSS hunter
	"xsshunters_view":          true,
	"xsshunter_view":           true,
	"xsshunter_payload_view":   true,
	"xsshunter_payload_create": true,
	"xsshunter_create":         true,
	"xsshunter_edit":           true,
	"xsshunter_delete":         true,
	"xsshunter_clean":          true,

	//Logs
	"logs": true,
	//SSL certs
	"certs": true,
}
