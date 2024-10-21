package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) RecordByID(id string) (*ds.Record, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.Record{}, err
	}
	var result ds.Record
	err = dao.Client.Database(dao.DNSDatabase).Collection("records").FindOne(context_get(), bson.M{"_id": objId}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.Record{}, nil
	} else if err != nil {
		return &ds.Record{}, err
	}
	return &result, nil
}

func (dao *Dao) RecordByTypeAndName(tld, tp string) (*[]ds.Record, error) {
	var results []ds.Record
	findOptions := options.Find()
	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("records").Find(context_get(), bson.M{"type": tp, "tld": tld},findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Record{}, nil
	} else if err != nil {
		return &[]ds.Record{}, err
	}
	cursor.All(context_get(), &results)
	return &results, nil
}

func (dao *Dao) RecordByName(tld string) (*[]ds.Record, error) {
	var results []ds.Record
	findOptions := options.Find()
	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("records").Find(context_get(), bson.M{"tld": tld},findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Record{}, nil
	} else if err != nil {
		return &[]ds.Record{}, err
	}
	cursor.All(context_get(), &results)
	return &results, nil
}

func (dao *Dao) RecordExists(tld, tp string) (bool, error) {
	err := dao.Client.Database(dao.DNSDatabase).Collection("records").FindOne(context_get(), bson.M{"type": tp, "tld": tld}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) RecordEdit(record *ds.Record) (bool, error) {
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("records").ReplaceOne(context_get(),
		bson.M{"_id": record.Id},
		record)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) RecordDelete(id string) (bool, error) {
	objId, _ := primitive.ObjectIDFromHex(id)
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("records").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) RecordAdd(record *ds.Record) (string, error) {
	record.Id = primitive.NewObjectID()

	_, err := dao.Client.Database(dao.DNSDatabase).Collection("records").InsertOne(context_get(), record)
	if err != nil {
		return "", err
	}
	return record.Id.Hex(), nil
}

func (dao *Dao) AllRecords() (*[]ds.Record, error) {
	var records []ds.Record
	findOptions := options.Find()

	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("records").Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Record{}, nil
	} else if err != nil {
		return &[]ds.Record{}, err
	}
	cursor.All(context_get(), &records)
	return &records, nil
}
