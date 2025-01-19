package main

import (
	"github.com/op/go-logging"
	"os"
)

var (
	log    = logging.MustGetLogger("main")
	format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} [%{pid}] %{level:.4s} %{shortfunc} ▶%{color:reset} %{message}`,
	)
)

func initialiseLogger() {
	backend := logging.NewLogBackend(os.Stdout, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(formatter)
}
