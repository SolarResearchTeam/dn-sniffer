package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (dao *Dao) GetAllZones() (*[]ds.Zone_settings, error) {
	zones := []ds.Zone_settings{}
	cursor, err := dao.Client.Database(dao.DNSDatabase).Collection("settings").Find(context_get(), bson.M{})
	if err != nil && err == mongo.ErrNoDocuments {
		return &zones, nil
	} else if err != nil {
		return &zones, err
	}
	cursor.All(context_get(), &zones)
	return &zones, nil
}

func (dao *Dao) GetZone(id string) (*ds.Zone_settings, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.Zone_settings{}, err
	}
	var zone ds.Zone_settings
	err = dao.Client.Database(dao.DNSDatabase).Collection("settings").FindOne(context_get(), bson.M{"_id": objId}).Decode(&zone)
	if err != nil && err == mongo.ErrNoDocuments {
		return &ds.Zone_settings{}, nil
	} else if err != nil {
		return &ds.Zone_settings{}, err
	}
	return &zone, nil

}

func (dao *Dao) TLDExist(tld string) (bool, error) {
	err := dao.Client.Database(dao.DNSDatabase).Collection("settings").FindOne(context_get(), bson.M{"tld": tld}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) ZoneNew(zone *ds.Zone_settings) (bool, error) {
	zone.Id = primitive.NewObjectID()
	_, err := dao.Client.Database(dao.DNSDatabase).Collection("settings").InsertOne(context_get(), zone)

	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) ZoneDelete(id string) error {
	zone, err := dao.GetZone(id)
	if err != nil {
		return err
	}
	if zone == nil {
		return nil
	}
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	err = dao.Client.Database(dao.HitsDatabase).Collection(zone.TLD).Drop(context_get())
	if err != nil {
		return err
	}
	_, err = dao.Client.Database(dao.DNSDatabase).Collection("settings").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return err
	}
	return nil
}

func (dao *Dao) ZoneClean(id string) error {
	if id != "other" {
		zone, err := dao.GetZone(id)
		if err != nil {
			return err
		}
		if zone == nil {
			return nil
		}
		err = dao.Client.Database(dao.HitsDatabase).Collection(zone.TLD).Drop(context_get())
		if err != nil {
			return err
		}
	} else {
		err := dao.Client.Database(dao.HitsDatabase).Collection("other").Drop(context_get())
		if err != nil {
			return err
		}
	}
	return nil
}
