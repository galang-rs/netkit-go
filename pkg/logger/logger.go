package logger

import (
	"fmt"
	"io"
	"os"
)

var Enabled bool = true
var Output io.Writer = os.Stdout

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

func Infof(format string, a ...interface{}) {
	fmt.Fprint(Output, colorGreen)
	fmt.Fprintf(Output, format, a...)
	fmt.Fprint(Output, colorReset)
}

func Warnf(format string, a ...interface{}) {
	fmt.Fprint(Output, colorYellow)
	fmt.Fprintf(Output, format, a...)
	fmt.Fprint(Output, colorReset)
}

func Successf(format string, a ...interface{}) {
	fmt.Fprint(Output, colorGreen)
	fmt.Fprintf(Output, format, a...)
	fmt.Fprint(Output, colorReset)
}

func Errorf(format string, a ...interface{}) error {
	err := fmt.Errorf(format, a...)
	msg := err.Error()
	fmt.Fprint(Output, colorRed)
	fmt.Fprint(Output, msg)
	fmt.Fprint(Output, colorReset)
	return err
}

func Printf(format string, a ...interface{}) {
	fmt.Fprint(Output, colorGreen)
	fmt.Fprintf(Output, format, a...)
	fmt.Fprint(Output, colorReset)
}

func Println(a ...interface{}) {
	fmt.Fprint(Output, colorGreen)
	fmt.Fprintln(Output, a...)
	fmt.Fprint(Output, colorReset)
}
