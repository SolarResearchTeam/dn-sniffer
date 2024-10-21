package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetAllLogs(limit int, skip int) (*[]ds.Log, error) {
	dbclient := dao.Client
	dbcontext := context_get()
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var logs []ds.Log
	cursor, err := dbclient.Database(dao.MainDatabase).Collection("logs").Find(dbcontext, bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Log{}, nil
	} else if err != nil {
		return &[]ds.Log{}, err
	}

	cursor.All(dbcontext, &logs)
	return &logs, nil
}

func (dao *Dao) GetLogsByQuery(limit int, skip int, search string) (*[]ds.Log, error) {
	dbclient := dao.Client
	dbcontext := context_get()
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var logs []ds.Log

	query := bson.M{"$or": []bson.M{
		{"source": bson.M{"$regex": search}},
		{"message": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
		{"level": bson.M{"$regex": search}},
	},
	}
	cursor, err := dbclient.Database(dao.MainDatabase).Collection("logs").Find(dbcontext, query, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Log{}, nil
	} else if err != nil {
		return &[]ds.Log{}, err
	}
	cursor.All(dbcontext, &logs)
	return &logs, nil
}

func (dao *Dao) AddLog(log *ds.Log) error {
	dbclient := dao.Client
	dbcontext := context_get()
	log.Id = primitive.NewObjectID()

	_, err := dbclient.Database(dao.MainDatabase).Collection("logs").InsertOne(dbcontext, log)
	if err != nil {
		return err
	}
	return nil
}

func (dao *Dao) GetLogCountByQuery(search string) (int, error) {
	dbclient := dao.Client
	dbcontext := context_get()
	query := bson.M{"$or": []bson.M{
		{"source": bson.M{"$regex": search}},
		{"message": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
		{"level": bson.M{"$regex": search}},
	},
	}
	count, err := dbclient.Database(dao.MainDatabase).Collection("logs").CountDocuments(dbcontext, query)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) GetLogCount() (int, error) {
	dbclient := dao.Client
	dbcontext := context_get()
	findOptions := options.Find()
	count, err := dbclient.Database(dao.MainDatabase).Collection("logs").CountDocuments(dbcontext, findOptions)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}
