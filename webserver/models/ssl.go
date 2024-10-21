package models

import (
	"errors"
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)



func (dao *Dao) GetAllRenewers() (*[]ds.SSLRenewer, error) {
	findOptions := options.Find()
	var renewers []ds.SSLRenewer
	cursor, err := dao.Client.Database(dao.MainDatabase).Collection("ssl").Find(context_get(), bson.M{}, findOptions)
	if err != nil {
		return &[]ds.SSLRenewer{}, err
	}
	cursor.All(context_get(), &renewers)
	return &renewers, nil
}

func (dao *Dao) GetRenewer(domain string) (bool, error) {
	err := dao.Client.Database(dao.MainDatabase).Collection("ssl").FindOne(context_get(), bson.M{"domain": domain}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) AddRenewer(domain string) (bool, error) {
	exist,_ := dao.GetRenewer(domain)
	if exist {
		return false, errors.New("Renewer already exist")
	}
	renewer := ds.SSLRenewer{}
	renewer.Id = primitive.NewObjectID()
	renewer.Domain = domain

	_, err := dao.Client.Database(dao.MainDatabase).Collection("ssl").InsertOne(context_get(), &renewer)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) DelRenewer(domain string) (bool, error) {
	_, err := dao.Client.Database(dao.MainDatabase).Collection("ssl").DeleteOne(context_get(), bson.M{"domain": domain})
	if err != nil {
		return false, err
	}
	return true, nil
}