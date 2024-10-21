package datastructures

import "go.mongodb.org/mongo-driver/bson/primitive"

type HunterPayload struct {
	Name    string `bson:"payloadname"`
	Payload string `bson:"payload"`
	Sample  string `bson:"sample"`
}

type HunterHit struct {
	Id          primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	HunterUUID  string             `bson:"uuid"`
	Time        string             `bson:"time"`
	IP          string             `bson:"ip"`
	Screen      string             `bson:"screen"`
	Uri         string             `bson:"uri"`
	PageHTML    string             `bson:"pagehtml"`
	Cookies     string             `bson:"cookies"`
	UserAgent   string             `bson:"ua"`
	BrowserTime string             `bson:"browsertime"`
	Origin      string             `bson:"origin"`
}

type HunterPGP struct {
	PrivateKey string `bson:"privatekey"`
	PublicKey  string `bson:"publickey"`
}

type HunterSetting struct {
	Id              primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	UUID            string             `bson:"uuid"`
	Name            string             `bson:"name"`
	Domain 			string			   `bson:"domain"`	
	MotherShipToken string             `bson:"mstoken"`
	MotherShipUrl   string             `bson:"msurl"`
	Payload         HunterPayload      `bson:"payload"`
	PGP             HunterPGP          `bson:"pgp"`
}

type HunterPayloadSample struct {
	Name          string
	PayloadSample string
}

type HunterSettings struct {
	Id           primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	SettingName  string             `bson:"setting_name"`
	SettingValue string             `bson:"setting_value"`
}

type Hunter struct {
	UUID    string
	TLD     string
	Hits    *[]HunterHit
	Record  *[]HunterRecord
	Setting *HunterSetting
}

type HunterRecord struct {
	Id    primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Type  string             `bson:"type"`
	Name  string             `bson:"name"`
	Value string             `bson:"value"`
}
