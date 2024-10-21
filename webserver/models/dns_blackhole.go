package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetAllBlackHole() (*[]ds.BlackHole, error) {
	var records []ds.BlackHole
	findOptions := options.Find()

	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.BlackHole{}, nil
	} else if err != nil {
		return &[]ds.BlackHole{}, err
	}
	cursor.All(context_get(), &records)
	return &records, nil
}

func (dao *Dao) BlackHoleExist(rebind_domain string, rebind_ip string) (bool, error) {
	err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").FindOne(context_get(), bson.M{"$and": []bson.M{{"domain": rebind_domain}, {"fromip": rebind_ip}}}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) InBlackHole(rebind_domain string, rebind_ip string) (bool, error) {
	var res ds.BlackHole
	search := bson.M{"$or": []bson.M{
		{"$and": []bson.M{
			{"domain": rebind_domain},
			{"fromip": rebind_ip},
		}},
		{"$and": []bson.M{
			{"domain": "*"},
			{"fromip": rebind_ip},
		}},
		{"$and": []bson.M{
			{"domain": rebind_domain},
			{"fromip": "*"},
		}},
	},
	}
	err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").FindOne(context_get(), search).Decode(&res)
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) GetBlackHole(rebind_domain string) (*ds.BlackHole, error) {
	var res ds.BlackHole
	err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").FindOne(context_get(), bson.M{"domain": rebind_domain}).Decode(&res)
	if err == mongo.ErrNoDocuments {
		return &ds.BlackHole{}, nil
	} else if err != nil {
		return &ds.BlackHole{}, err
	}
	return &res, nil
}

func (dao *Dao) BlackHoleNew(rebind *ds.BlackHole) (bool, error) {
	rebind.Id = primitive.NewObjectID()
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").InsertOne(context_get(), rebind)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) BlackHoleByID(id string) (*ds.BlackHole, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.BlackHole{}, err
	}
	var result ds.BlackHole
	err = dao.Client.Database(dao.DNSDatabase).Collection("blackhole").FindOne(context_get(), bson.M{"_id": objId}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.BlackHole{}, nil
	} else if err != nil {
		return &ds.BlackHole{}, err
	}
	return &result, nil
}

func (dao *Dao) BlackHoleUpdate(rebind *ds.BlackHole) (bool, error) {
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("blackhole").ReplaceOne(context_get(),
		bson.M{"_id": rebind.Id},
		rebind)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) BlackHoleDelete(id string) (bool, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return false, err
	}
	_, err = dao.Client.Database(dao.DNSDatabase).Collection("blackhole").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return false, err
	}
	return true, nil
}
