package datastructures

import "go.mongodb.org/mongo-driver/bson/primitive"

type SSLRenewer struct {
	Id          primitive.ObjectID 	`bson:"_id" json:"id,omitempty"`
	Domain 		string				`bson:"domain"`
}
