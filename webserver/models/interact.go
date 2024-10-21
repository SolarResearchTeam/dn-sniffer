package models

import (
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (dao *Dao) GetAllInteract() (*[]ds.Interact_server, error) {
	findOptions := options.Find()
	var interacts []ds.Interact_server
	cursor, err := dao.Client.Database(dao.InteractDatabase).Collection("interacts").Find(context_get(), bson.M{}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Interact_server{}, nil
	} else if err != nil {
		return &[]ds.Interact_server{}, err
	}
	cursor.All(context_get(), &interacts)
	return &interacts, nil
}

func (dao *Dao) GetInteractHitsCount() (int, error) {
	findOptions := options.Find()
	count, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").CountDocuments(context_get(), findOptions)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) GetInteractById(id string) (*ds.Interact_server, error) {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return &ds.Interact_server{}, err
	}
	var result ds.Interact_server
	err = dao.Client.Database(dao.InteractDatabase).Collection("interacts").FindOne(context_get(), bson.M{"_id": objId}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.Interact_server{}, nil
	} else if err != nil {
		return &ds.Interact_server{}, err
	}
	return &result, nil
}

func (dao *Dao) GetIneractOnAdminPort(port int) (*ds.Interact_server, error) {
	var result ds.Interact_server
	err := dao.Client.Database(dao.InteractDatabase).Collection("interacts").FindOne(context_get(), bson.M{"$and": []bson.M{bson.M{"port": port},bson.M{"running":true}}}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return &ds.Interact_server{}, nil
	} else if err != nil {
		return &ds.Interact_server{}, err
	}
	return &result, nil
}



func (dao *Dao) GetInteractHitsById(limit int, skip int, id string) (*[]ds.Interact_hit, error) {
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var hits []ds.Interact_hit
	cursor, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").Find(context_get(), bson.M{"server_id": id}, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Interact_hit{}, nil
	} else if err != nil {
		return &[]ds.Interact_hit{}, err
	}
	cursor.All(context_get(), &hits)
	return &hits, nil
}

func (dao *Dao) GetCountInteractHitsById(id string) (int, error) {
	count, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").CountDocuments(context_get(), bson.M{"server_id": id})
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (dao *Dao) GetInteractHitsByQuery(limit int, skip int, id string, search string) (*[]ds.Interact_hit, error) {
	findOptions := options.Find().SetSort(bson.D{{"_id", -1}})
	if limit > 0 {
		findOptions = findOptions.SetLimit(int64(limit))
		if skip > 0 {
			findOptions = findOptions.SetSkip(int64(skip))
		}
	}
	var hits []ds.Interact_hit
	query := bson.M{"$and": []bson.M{
		bson.M{"server_id": id},
		bson.M{"$or": []bson.M{
			{"client_addr": bson.M{"$regex": search}},
			{"content": bson.M{"$regex": search}},
		},
		},
	},
	}
	cursor, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").Find(context_get(), query, findOptions)
	if err == mongo.ErrNoDocuments {
		return &[]ds.Interact_hit{}, nil
	} else if err != nil {
		return &[]ds.Interact_hit{}, err
	}
	cursor.All(context_get(), &hits)
	return &hits, nil
}

func (dao *Dao) GetCountInteractHitsByQuery(id string, search string) (int, error) {
	query := bson.M{"$and": []bson.M{
		bson.M{"server_id": id},
		bson.M{"$or": []bson.M{
			{"client_addr": bson.M{"$regex": search}},
			{"content": bson.M{"$regex": search}},
		},
		},
	},
	}
	count, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").CountDocuments(context_get(), query)
	if err == mongo.ErrNoDocuments {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return int(count), err
}

func (dao *Dao) InteractClear(id string) (bool, error) {
	_, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").DeleteMany(context_get(), bson.M{"server_id": id})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) AddInteract(interact *ds.Interact_server) (string, error) {
	interact.Id = primitive.NewObjectID()
	result, err := dao.Client.Database(dao.InteractDatabase).Collection("interacts").InsertOne(context_get(), interact)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (dao *Dao) InteractDel(id string) (bool, error) {
	objId, _ := primitive.ObjectIDFromHex(id)
	_, err := dao.Client.Database(dao.InteractDatabase).Collection("interacts").DeleteOne(context_get(), bson.M{"_id": objId})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) EditInteract(interact *ds.Interact_server) (bool, error) {
	_, err := dao.Client.Database(dao.InteractDatabase).Collection("interacts").ReplaceOne(context_get(),
		bson.M{"_id": interact.Id},
		interact)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (dao *Dao) AddInteractHit(hit *ds.Interact_hit) (bool, error) {
	hit.Id = primitive.NewObjectID()

	_, err := dao.Client.Database(dao.InteractDatabase).Collection("hits").InsertOne(context_get(), hit)
	if err != nil {
		return false, err
	}
	return true, nil
}
