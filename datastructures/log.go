package datastructures

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Log struct {
	Id      primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Level   string             `bson:"level"`
	Source  string             `bson:"source"`
	Time    string             `bson:"time"`
	Message string             `bson:"message"`
}