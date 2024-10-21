package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetUserByName(username string) (*ds.Users, error) {
	partialresults := false
	options := options.FindOneOptions{
		AllowPartialResults: &partialresults,
	}
	var result ds.Users
	err := dao.Client.Database(dao.MainDatabase).Collection("users").FindOne(context_get(), bson.M{"username": bson.M{"$regex": primitive.Regex{Pattern: "^" + username + "$", Options: "i"}}}, &options).Decode(&result)
	if err != nil && err == mongo.ErrNoDocuments{
		return &ds.Users{}, nil 
	} else if err != nil {
		return &ds.Users{}, err 
	}
	return &result, nil
}

func (dao *Dao) GetAllUsers() (*[]ds.Users, error) {
	findOptions := options.Find()
	var users []ds.Users
	cursor, err := dao.Client.Database(dao.MainDatabase).Collection("users").Find(context_get(), bson.M{}, findOptions)
	if err != nil {
		return &[]ds.Users{}, err
	}
	cursor.All(context_get(), &users)
	return &users, nil
}

func (dao *Dao) GetUserById(id string) (*ds.Users, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.Users{}, err
	}
	var result ds.Users
	err = dao.Client.Database(dao.MainDatabase).Collection("users").FindOne(context_get(), bson.M{"_id": objId}).Decode(&result)
	if err != nil && err == mongo.ErrNoDocuments{
		return &ds.Users{}, nil 
	} else if err != nil {
		return &ds.Users{}, err 
	}
	return &result, nil
}

func (dao *Dao) GetUserByEmail(email string) (*ds.Users, error) {
	var result ds.Users
	err := dao.Client.Database(dao.MainDatabase).Collection("users").FindOne(context_get(), bson.M{"email": email}).Decode(&result)
	if err != nil && err == mongo.ErrNoDocuments{
		return &ds.Users{}, nil 
	} else if err != nil {
		return &ds.Users{}, err 
	}
	return &result, nil
}

func (dao *Dao) AddUser(user *ds.Users) (bool, error) {
	user.Id = primitive.NewObjectID()

	_, err := dao.Client.Database(dao.MainDatabase).Collection("users").InsertOne(context_get(), user)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) UserDelete(id string) (bool, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return false, err
	}
	_, err = dao.Client.Database(dao.MainDatabase).Collection("users").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) EditUser(user *ds.Users) (bool, error) {
	_, err := dao.Client.Database(dao.MainDatabase).Collection("users").ReplaceOne(context_get(),
		bson.M{"_id": user.Id},
		user)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) GetUserByRestoreToken(restoretoken string) (*ds.Users, error) {
	var result ds.Users
	err := dao.Client.Database(dao.MainDatabase).Collection("users").FindOne(context_get(), bson.M{"restoretoken": restoretoken}).Decode(&result)
	if err != nil && err == mongo.ErrNoDocuments{
		return &ds.Users{}, nil 
	} else if err != nil {
		return &ds.Users{}, err 
	}
	return &result, nil
}
