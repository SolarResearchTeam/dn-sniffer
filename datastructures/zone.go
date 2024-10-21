package datastructures

import "go.mongodb.org/mongo-driver/bson/primitive"

type Record struct {
	Id    primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Type  string             `bson:"type"`
	TLD  string             `bson:"tld"`
	Value string             `bson:"value"`
}

type Hit struct {
	Id         primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	DomainName string             `bson:"domain"`
	Time       string             `bson:"time"`
	IP         string             `bson:"ip"`
}

type Zone struct {
	Id        string
	Name      string	`bson:"ip"`
	TLD       string	`bson:"tld"`

	TotalHits int
	Hits      *[]Hit
	Record    *[]Record
}

type Zone_settings struct {
	Id        primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name      string	`bson:"Name"`
	TLD       string	`bson:"tld"`
}