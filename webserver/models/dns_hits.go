package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetHitsByZone(limit int, skip int, zonename string) ([]ds.Hit, error) {
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var hits []ds.Hit
	cursor, err := dao.Client.Database(dao.HitsDatabase).Collection(zonename).Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return []ds.Hit{}, nil
	} else if err != nil {
		return []ds.Hit{}, err
	}

	cursor.All(context_get(), &hits)
	return hits, nil
}

func (dao *Dao) GetHitsByQuery(limit int, skip int, zonename string, search string) ([]ds.Hit, error) {
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var hits []ds.Hit

	query := bson.M{"$or": []bson.M{
		{"domain": bson.M{"$regex": search}},
		{"ip": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
	},
	}
	cursor, err := dao.Client.Database(dao.HitsDatabase).Collection(zonename).Find(context_get(), query, findOptions)
	if err == mongo.ErrNoDocuments {
		return []ds.Hit{}, nil
	} else if err != nil {
		return []ds.Hit{}, err
	}
	cursor.All(context_get(), &hits)
	return hits, nil
}

func (dao *Dao) GetCountByQuery(zonename string, search string) (int, error) {
	query := bson.M{"$or": []bson.M{
		{"domain": bson.M{"$regex": search}},
		{"ip": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
	},
	}
	count, err := dao.Client.Database(dao.HitsDatabase).Collection(zonename).CountDocuments(context_get(), query)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) GetCountByZone(zonename string) (int, error) {
	findOptions := options.Find()
	count, err := dao.Client.Database(dao.HitsDatabase).Collection(zonename).CountDocuments(context_get(), findOptions)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) WriteHit(zonename string, hit *ds.Hit) (bool, error) {
	hit.Id = primitive.NewObjectID()

	_, err := dao.Client.Database(dao.HitsDatabase).Collection(zonename).InsertOne(context_get(), hit)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) ZoneCleaner(domain string, ip string) (bool, error) {
	var filter bson.M
	if domain != "*" && ip != "*" {
		filter = bson.M{
			"$and": []bson.M{
				{"domain": domain},
				bson.M{"ip": bson.M{"$regex": (ip + ":[0-9]*")}},
			},
		}
	} else if ip == "*" {
		filter = bson.M{"domain": domain}
	} else {
		filter = bson.M{"ip": bson.M{"$regex": (ip + ":[0-9]*")}}
	}

	zones, _ := dao.Client.Database(dao.HitsDatabase).ListCollectionNames(context_get(), bson.M{})
	for _, zone := range zones {
		_, err := dao.Client.Database(dao.HitsDatabase).Collection(zone).DeleteMany(context_get(), filter)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (dao *Dao) GetCountAllZone() (int, error) {
	zones, _ := dao.Client.Database(dao.HitsDatabase).ListCollectionNames(context_get(), bson.M{})
	all_count := 0
	for _, zone := range zones {
		findOptions := options.Find()
		count, err := dao.Client.Database(dao.HitsDatabase).Collection(zone).CountDocuments(context_get(), findOptions)
		if err == mongo.ErrNoDocuments {
			continue
		} else if err != nil {
			return 0, err
		}
		all_count = all_count + int(count)
	}
	return all_count, nil
}

func (dao *Dao) GetCountAllZoneByQuery(search string) (int, error) {
	zones, _ := dao.Client.Database(dao.HitsDatabase).ListCollectionNames(context_get(), bson.M{})
	all_count := 0
	query := bson.M{"$or": []bson.M{
		{"domain": bson.M{"$regex": search}},
		{"ip": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
	},
	}
	for _, zone := range zones {
		count, err := dao.Client.Database(dao.HitsDatabase).Collection(zone).CountDocuments(context_get(), query)
		if err == mongo.ErrNoDocuments {
			continue
		} else if err != nil {
			return 0, err
		}
		all_count = all_count + int(count)
	}
	return all_count, nil
}

func (dao *Dao) GetAllHits(limit int, skip int) ([]ds.Hit, error) {
	zones, _ := dao.Client.Database(dao.HitsDatabase).ListCollectionNames(context_get(), bson.M{})
	coll := dao.Client.Database(dao.HitsDatabase).Collection("other")
	unionStage := make([]bson.M, 0)
	for _, zone := range zones {
		if zone != "other" {
			unionStage = append(unionStage, bson.M{"$unionWith": bson.M{"coll": zone}})
		}
	}
	sortStage := bson.M{"$sort": bson.M{"_id": -1}}
	skipStage := bson.M{"$skip": skip}
	limitStage := bson.M{"$limit": limit}

	completePipeline := []bson.M{}
	completePipeline = append(completePipeline, unionStage...)
	completePipeline = append(completePipeline, sortStage)
	completePipeline = append(completePipeline, skipStage)
	completePipeline = append(completePipeline, limitStage)

	var hits []ds.Hit
	cursor, err := coll.Aggregate(context_get(), completePipeline)
	if err == mongo.ErrNoDocuments {
		return []ds.Hit{}, nil
	} else if err != nil {
		return []ds.Hit{}, err
	}
	cursor.All(context_get(), &hits)
	return hits, nil
}

func (dao *Dao) GetAllHitsByQuery(limit int, skip int, search string) ([]ds.Hit, error) {
	zones, _ := dao.Client.Database(dao.HitsDatabase).ListCollectionNames(context_get(), bson.M{})
	coll := dao.Client.Database(dao.HitsDatabase).Collection("other")
	unionStage := []bson.M{}
	for _, zone := range zones {
		if zone != "other" {
			unionStage = append(unionStage, bson.M{"$unionWith": bson.M{"coll": zone}})
		}
	}

	query := bson.M{"$or": []bson.M{
		{"domain": bson.M{"$regex": search}},
		{"ip": bson.M{"$regex": search}},
		{"time": bson.M{"$regex": search}},
	},
	}
	searchStage := bson.M{"$match": query}
	sortStage := bson.M{"$sort": bson.M{"_id": -1}}
	skipStage := bson.M{"$skip": skip}
	limitStage := bson.M{"$limit": limit}

	completePipeline := []bson.M{}
	completePipeline = append(completePipeline, unionStage...)
	completePipeline = append(completePipeline, searchStage)
	completePipeline = append(completePipeline, sortStage)
	completePipeline = append(completePipeline, skipStage)
	completePipeline = append(completePipeline, limitStage)

	var hits []ds.Hit
	cursor, err := coll.Aggregate(context_get(), completePipeline)
	if err == mongo.ErrNoDocuments {
		return []ds.Hit{}, nil
	} else if err != nil {
		return []ds.Hit{}, err
	}
	cursor.All(context_get(), &hits)
	return hits, nil
}
