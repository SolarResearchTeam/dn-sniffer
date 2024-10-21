package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetAllRebinds() (*[]ds.Rebind, error) {
	var records []ds.Rebind
	findOptions := options.Find()

	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("rebind").Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Rebind{}, nil
	} else if err != nil {
		return &[]ds.Rebind{}, err
	}

	cursor.All(context_get(), &records)
	return &records, nil
}

func (dao *Dao) RebindExist(rebind_domain string) (bool, error) {
	err := dao.Client.Database(dao.DNSDatabase).Collection("rebind").FindOne(context_get(), bson.M{"domain": rebind_domain}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) GetRebind(rebind_domain string) (*ds.Rebind, error) {
	var res ds.Rebind
	err := dao.Client.Database(dao.DNSDatabase).Collection("rebind").FindOne(context_get(), bson.M{"domain": rebind_domain}).Decode(&res)
	if err == mongo.ErrNoDocuments {
		return &ds.Rebind{}, nil
	} else if err != nil {
		return &ds.Rebind{}, err
	}
	return &res, nil
}

func (dao *Dao) RebindNew(rebind *ds.Rebind) (bool, error) {
	rebind.Id = primitive.NewObjectID()
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("rebind").InsertOne(context_get(), rebind)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) RebindByID(id string) (*ds.Rebind, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.Rebind{}, err
	}
	var result ds.Rebind
	err = dao.Client.Database(dao.DNSDatabase).Collection("rebind").FindOne(context_get(), bson.M{"_id": objId}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.Rebind{}, nil
	} else if err != nil {
		return &ds.Rebind{}, err
	}
	return &result, nil
}

func (dao *Dao) RebindUpdate(rebind *ds.Rebind) (bool, error) {
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("rebind").ReplaceOne(context_get(),
		bson.M{"_id": rebind.Id},
		rebind)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) RebindDelete(id string) (bool, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return false, err
	}
	_, err = dao.Client.Database(dao.DNSDatabase).Collection("rebind").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return false, err
	}
	return true, nil
}
