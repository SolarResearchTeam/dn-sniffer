package models

import (
	"context"

	"time"

	"github.com/SolarResearchTeam/dn-sniffer/config"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Database = Dao{}

type Dao struct {
	MongoUrl          string
	Client            *mongo.Client
	Context           context.Context
	MainDatabase      string
	DNSDatabase       string
	HitsDatabase      string
	InteractDatabase  string
	XSSHunterDatabase string
	MongoUser         string
	MongoPassword     string
}

func NewDao(conf *config.Config) error {
	Database = Dao{
		MongoUrl:          conf.MongoConf.MongoDBPath,

		MainDatabase:      conf.MongoConf.MongoMainDBName,

		DNSDatabase:      conf.MongoConf.MongoDNSDBName,
		HitsDatabase:      conf.MongoConf.MongoHitsDBName,

		InteractDatabase:  conf.MongoConf.MongoInteractDBName,

		XSSHunterDatabase: conf.MongoConf.MongoXSSHunterDBName,

		MongoUser:         conf.MongoConf.MongoDBUser,
		MongoPassword:     conf.MongoConf.MongoDBPassword,
	}
	var cred options.Credential
	cred.Username = conf.MongoConf.MongoDBUser
	cred.Password = conf.MongoConf.MongoDBPassword

	client, err := mongo.Connect(context.TODO(),options.Client().ApplyURI(Database.MongoUrl).SetAuth(cred).SetServerSelectionTimeout(10*time.Second))
	if err != nil {
		return err
	}
	Database.Client = client
	err = Database.Client.Ping(context.TODO(),nil)
	return err 
}

func context_get() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 20*time.Second)
	return ctx
}

func (dao *Dao) Init() error {
	adminpasswd, _ := utils.GeneratePasswordHash("admin")
	adminuser := ds.Users{
		Id:                     primitive.NewObjectID(),
		Username:               "admin",
		Email:                  "admin@notexist.notexist",
		FirstName:              "admin",
		LastName:               "admin",
		Password:               adminpasswd,
		IsLocked:               false,
		PasswordChangeRequired: true,
		Role:                   "admin",
		Rights: 				ds.RightsAdmin,
	}

	dao.Client.Database(dao.HitsDatabase).Collection("other")
	userscollection := dao.Client.Database(dao.MainDatabase).Collection("users")
	count2, _ := userscollection.CountDocuments(context_get(), bson.D{})
	if count2 == 0 {
		_, err := userscollection.InsertOne(context_get(), adminuser)
		if err != nil {
			return err
		}
	}
	return nil
}
