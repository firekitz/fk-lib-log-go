package log

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/sirupsen/logrus"
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
	Port     int
	DB       int
	TTL      int
}

// RedisHook to sends logs to Redis server
type RedisHook struct {
	RedisPool   *redis.Pool
	RedisHost   string
	RedisKey    string
	RedisPort   int
	TTL         int
	DialOptions []redis.DialOption
}

// Init config := HookConfig{
//	Host:     "redis host",
//	Key:      "key",
//	Password: "password",
//	Port:     6379,
//	DB:       0,
//	TTL:      3600,
//}
//
// var label []string = {"domainId, appId, env, slackId"}
func Init(config HookConfig, label []string) error {
	Label = label
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
	log = logRedis.WithFields(logrus.Fields{
		"meta": logrus.Fields{
			"label":     label,
			"timestamp": time.Now().UTC(),
		},
	})

	hook, err := NewHook(config)
	if err != nil {
		return err
	}
	logRedis.AddHook(hook)
	return nil
}

// NewHook creates a hook to be added to an instance of logger
func NewHook(config HookConfig, options ...redis.DialOption) (*RedisHook, error) {
	pool := newRedisConnectionPool(config.Host, config.Password, config.Port, config.DB, options...)

	// test if connection with REDIS can be established
	conn := pool.Get()
	defer conn.Close()

	// check connection
	_, err := conn.Do("PING")
	if err != nil {
		return nil, fmt.Errorf("unable to connect to REDIS: %s", err)
	}

	return &RedisHook{
		RedisHost:   config.Host,
		RedisPool:   pool,
		RedisKey:    config.Key,
		TTL:         config.TTL,
		DialOptions: options,
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

	// Marshal into json message
	js, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error creating message for REDIS: %s", err)
	}
	// get connection from pool
	conn := hook.RedisPool.Get()
	defer conn.Close()

	// send message
	_, err = conn.Do("RPUSH", hook.RedisKey, js)
	if err != nil {
		return fmt.Errorf("error sending message to REDIS: %s", err)
	}

	if hook.TTL != 0 {
		_, err = conn.Do("EXPIRE", hook.RedisKey, hook.TTL)
		if err != nil {
			return fmt.Errorf("error setting TTL to key: %s, %s", hook.RedisKey, err)
		}
	}

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

func newRedisConnectionPool(server, password string, port int, db int, options ...redis.DialOption) *redis.Pool {
	hostPort := fmt.Sprintf("%s:%d", server, port)
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			dialOptions := append([]redis.DialOption{
				redis.DialDatabase(db),
				redis.DialPassword(password),
			}, options...)
			c, err := redis.Dial("tcp", hostPort, dialOptions...)
			if err != nil {
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
}
