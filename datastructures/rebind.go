package datastructures

import "go.mongodb.org/mongo-driver/bson/primitive"

type Rebind struct {
	Id          primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Domain      string             `bson:"domain"`
	FromIP      string             `bson:"fromip"`
	ToIP        string             `bson:"toip"`
	Time        string             `bson:"time"`
	LastRequest int64              `bson:"lastrequest"`
}
