package log

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	fkBootstrap "github.com/firekitz/fk-lib-bootstrap-go"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"time"
)

// log Example
// Panic, Fatal, Error, Warn, Info, Debug, Trace
var log *logrus.Entry
var Label []string

// HookConfig stores configuration needed to setup the hook
type HookConfig struct {
	Key      string
	Host     string
	Password string
	Port     string
}

// RedisHook to sends logs to Redis server
type RedisHook struct {
	RedisClient *redis.Client
	RedisKey    string
}

// Init with config
func Init(env interface{}, TLS bool) (*RedisHook, error) {
	logRedis := logrus.New()
	logRedis.SetLevel(logrus.DebugLevel)
	logRedis.SetLevel(logrus.TraceLevel)
	logRedis.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp: true,
		FieldMap: logrus.FieldMap{
			"level":  "level",
			"msg":    "message",
			"caller": "caller",
		},
	})

	label, err := getLabel(env)
	if err != nil {
		return nil, err
	}
	log = logRedis.WithFields(logrus.Fields{
		"meta": logrus.Fields{
			"label":     label,
			"timestamp": time.Now().UTC(),
		},
	})

	config, err := getConfig(env)
	if err != nil {
		return nil, err
	}
	hook, err := newHook(config, TLS)
	if err != nil {
		return nil, err
	}
	logRedis.AddHook(hook)
	return hook, nil
}

func getConfig(env interface{}) (HookConfig, error) {
	var field []string
	field = append(field, "REDIS_LOG_HOST", "REDIS_LOG_PASSWORD", "REDIS_LOG_PORT", "REDIS_LOG_CONTAINER")
	res, err := fkBootstrap.GetFieldFromStruct(env, field)
	if err != nil {
		return HookConfig{}, fmt.Errorf("fk-lib-log-go struct error: %v", err)
	}
	return HookConfig{
		Key:      res["REDIS_LOG_CONTAINER"],
		Host:     res["REDIS_LOG_HOST"],
		Password: res["REDIS_LOG_PASSWORD"],
		Port:     res["REDIS_LOG_PORT"],
	}, nil
}

func getLabel(env interface{}) ([]string, error) {
	var field []string
	field = append(field, "DOMAIN_ID", "SERVICE_NAME", "ENV", "PROJECT_OWNER_SLACK_ID")
	res, err := fkBootstrap.GetFieldFromStruct(env, field)
	if err != nil {
		return nil, fmt.Errorf("fk-lib-log-go struct error: %v", err)
	}

	var label []string
	label = append(label, res["DOMAIN_ID"], res["SERVICE_NAME"], res["ENV"], res["PROJECT_OWNER_SLACK_ID"])
	return label, nil
}

// newHook creates a hook to be added to an instance of logger
func newHook(config HookConfig, TLS bool) (*RedisHook, error) {
	client := newClient(config, TLS)

	if _, err := client.Ping(context.Background()).Result(); err != nil {
		return nil, fmt.Errorf("fk-lib-log-go error: %v", err)
	}
	return &RedisHook{
		RedisClient: client,
		RedisKey:    config.Key,
	}, nil
}

func makeMessage(entry *logrus.Entry) map[string]interface{} {
	m := make(map[string]interface{})
	m["message"] = entry.Message
	m["level"] = entry.Level.String()
	for k, v := range entry.Data {
		m[k] = v
	}
	return m
}

// Fire is called when a log event is fired.
func (hook *RedisHook) Fire(entry *logrus.Entry) error {
	entry.WithFields(logrus.Fields{
		"meta": logrus.Fields{
			"label":     Label,
			"timestamp": time.Now().UTC(),
		},
	})
	data := makeMessage(entry)
	js, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error creating message for REDIS: %s", err)
	}
	if _, err = hook.RedisClient.RPush(context.Background(), hook.RedisKey, js).Result(); err != nil {
		return fmt.Errorf("error pushing message for REDIS: %s", err)
	}
	//if hook.TTL != 0 {
	//	if _, err = hook.RedisClient.Expire(context.Background(), hook.RedisKey, time.Duration(hook.TTL)).Result(); err != nil {
	//		return fmt.Errorf("error setting TTL to key: %s, %s", hook.RedisKey, err)
	//	}
	//}
	return nil
}

// Levels returns the available logging levels.
func (hook *RedisHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.TraceLevel,
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

func newClient(config HookConfig, TLS bool) *redis.Client {
	if TLS {
		return redis.NewClient(&redis.Options{
			Addr:      config.Host + ":" + config.Port,
			Password:  config.Password,
			DB:        0,
			TLSConfig: new(tls.Config),
		})
	} else {
		return redis.NewClient(&redis.Options{
			Addr:     config.Host + ":" + config.Port,
			Password: config.Password,
			DB:       0,
		})
	}
}

func (hook *RedisHook) Shutdown() error {
	if err := hook.RedisClient.Close(); err != nil {
		return fmt.Errorf("fk-lib-log-go shutdown error: %v", err)
	}
	return nil
}
