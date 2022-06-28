package log

func P(args ...interface{}) {
	log.Panic(args...)
}

func F(args ...interface{}) {
	log.Fatal(args...)
}

func E(args ...interface{}) {
	log.Error(args...)
}

func W(args ...interface{}) {
	log.Warn(args...)
}

func I(args ...interface{}) {
	log.Info(args...)
}

func D(args ...interface{}) {
	log.Debug(args...)
}

func T(args ...interface{}) {
	log.Trace(args...)
}
