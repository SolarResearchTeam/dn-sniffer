package datastructures

import "go.mongodb.org/mongo-driver/bson/primitive"

type Interact_server struct {
	Id     		primitive.ObjectID 	`bson:"_id" json:"id,omitempty"`
	Type 		string				`bson:"type"`
	ListenPort	int 				`bson:"port"`
	Running		bool				`bson:"running"`

	Sharing		bool				`bson:"sharing"`
	Errors		string				`bson:"errors"`			
}

type Interact_hit struct {
	Id     		primitive.ObjectID 	`bson:"_id" json:"id,omitempty"`
	ServerId	string				`bson:"server_id"`
	ClientAddr	string				`bson:"client_addr"`
	Content		string				`bson:"content"`
	Time       	string             	`bson:"time"`
}