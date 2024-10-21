package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetAllHunters() (*[]string, error) {
	result, err := dao.Client.Database(dao.XSSHunterDatabase).ListCollectionNames(context_get(), bson.M{})
	if err != nil {
		return &[]string{}, err
	}
	return &result, nil
}

func (dao *Dao) XssHunterGetAllHitsByUUID(uuid string) (*[]ds.HunterHit, error) {
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	var hits []ds.HunterHit
	cursor, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hits").Find(context_get(), bson.M{"uuid": uuid}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.HunterHit{}, nil
	} else if err != nil {
		return &[]ds.HunterHit{}, err
	}
	cursor.All(context_get(), &hits)
	return &hits, nil
}

func (dao *Dao) XssHunterGetSettingsByUuid(uuid string) (*ds.HunterSetting, error) {
	options := options.FindOne()
	var result ds.HunterSetting
	err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").FindOne(context_get(), bson.M{"uuid": bson.M{"$regex": primitive.Regex{Pattern: "^" + uuid + "$", Options: "i"}}}, options).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.HunterSetting{}, nil
	} else if err != nil {
		return &ds.HunterSetting{}, err
	}
	return &result, nil
}

func (dao *Dao) XssHunterGetByDomain(domain string) (bool, error) {
	err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").FindOne(context_get(), bson.M{"domain": domain}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) XssHunterGetSettingsByName(name string) (*ds.HunterSetting, error) {
	options := options.FindOne()
	var result ds.HunterSetting
	err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").FindOne(context_get(), bson.M{"name": bson.M{"$regex": primitive.Regex{Pattern: "^" + name + "$", Options: "i"}}}, options).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.HunterSetting{}, nil
	} else if err != nil {
		return &ds.HunterSetting{}, err
	}
	return &result, nil
}

func (dao *Dao) XssHunterAllSettings() (*[]ds.HunterSetting, error) {
	findOptions := options.Find()
	var settings []ds.HunterSetting
	cursor, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.HunterSetting{}, nil
	} else if err != nil {
		return &[]ds.HunterSetting{}, err
	}
	cursor.All(context_get(), &settings)
	return &settings, nil
}

func (dao *Dao) XssHunterNew(hunter *ds.HunterSetting) (bool, error) {
	hunter.Id = primitive.NewObjectID()
	_, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").InsertOne(context_get(), hunter)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) XssHunterByName(name string) (*ds.HunterSetting, error) {
	var result ds.HunterSetting
	err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").FindOne(context_get(), bson.M{"name": name}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.HunterSetting{}, nil
	} else if err != nil {
		return &ds.HunterSetting{}, err
	}
	return &result, nil
}

func (dao *Dao) XssHunterByUUID(uuid string) (*ds.HunterSetting, error) {
	var result ds.HunterSetting
	err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").FindOne(context_get(), bson.M{"uuid": uuid}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.HunterSetting{}, nil
	} else if err != nil {
		return &ds.HunterSetting{}, err
	}
	return &result, nil
}

func (dao *Dao) XssHunterAddHit(hit *ds.HunterHit) (bool, error) {
	hit.Id = primitive.NewObjectID()
	_, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hits").InsertOne(context_get(), hit)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) GetXssHunterHitsCount() (int, error) {
	findOptions := options.Find()
	count, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hits").CountDocuments(context_get(), findOptions)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) XssHunterDelete(uuid string) {
	dao.Client.Database(dao.XSSHunterDatabase).Collection(uuid).Drop(context_get())
	dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").DeleteOne(context_get(), bson.M{"uuid": uuid})
}

func (dao *Dao) XssHunterDeleteHits(uuid string) (bool, error) {
	_, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hits").DeleteMany(context_get(), bson.M{"uuid": uuid})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) XssHunterUpdateSettingsByUUID(uuid string, setting *ds.HunterSetting) (bool, error) {
	_, err := dao.Client.Database(dao.XSSHunterDatabase).Collection("hunters").ReplaceOne(context_get(),
		bson.M{"uuid": uuid},
		setting)
	if err != nil {
		return false, err
	}
	return true, nil
}
