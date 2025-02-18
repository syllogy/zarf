package message

import (
	"fmt"
	"os"
	"strings"

	"github.com/pterm/pterm"
)

type LogLevel int

const (
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel LogLevel = iota
	// InfoLevel level. General operational entries about what's going on inside the
	// application.
	InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel
	// TraceLevel level. Designates finer-grained informational events than the Debug.
	TraceLevel
)

var logLevel = InfoLevel

func init() {
	// Help capture text cleaner
	pterm.SetDefaultOutput(os.Stderr)
	pterm.ThemeDefault.SuccessMessageStyle = *pterm.NewStyle(pterm.FgLightGreen)
	// Customize default error.
	pterm.Success.Prefix = pterm.Prefix{
		Text:  " ✔",
		Style: pterm.NewStyle(pterm.FgLightGreen),
	}
	pterm.Error.Prefix = pterm.Prefix{
		Text:  "    ERROR:",
		Style: pterm.NewStyle(pterm.BgLightRed, pterm.FgBlack),
	}
	pterm.Info.Prefix = pterm.Prefix{
		Text: " •",
	}
}

func debugPrinter(offset int) *pterm.PrefixPrinter {
	return pterm.Debug.WithShowLineNumber(logLevel > 2).WithLineNumberOffset(offset)
}

func errorPrinter(offset int) *pterm.PrefixPrinter {
	return pterm.Error.WithShowLineNumber(logLevel > 2).WithLineNumberOffset(offset)
}

func SetLogLevel(lvl LogLevel) {
	logLevel = lvl
	if logLevel >= DebugLevel {
		pterm.EnableDebugMessages()
	}
}

func GetLogLevel() LogLevel {
	return logLevel
}

func Debug(payload ...interface{}) {
	debugPrinter(1).Println(payload...)
}

func Debugf(format string, a ...interface{}) {
	debugPrinter(2).Printfln(format, a...)
}

func Error(err interface{}, message string) {
	debugPrinter(1).Println(err)
	Warnf(message)
}

func Errorf(err interface{}, format string, a ...interface{}) {
	debugPrinter(1).Println(err)
	Warnf(format, a...)
}

func Warn(message string) {
	Warnf(message)
}

func Warnf(format string, a ...interface{}) {
	message := paragraph(format, a...)
	pterm.Warning.Println(message)
}

func Fatal(err interface{}, message string) {
	debugPrinter(1).Println(err)
	errorPrinter(1).Println(message)
	os.Exit(1)
}

func Fatalf(err interface{}, format string, a ...interface{}) {
	debugPrinter(1).Println(err)
	message := paragraph(format, a...)
	errorPrinter(1).Println(message)
	os.Exit(1)
}

func Info(message string) {
	Infof(message)
}

func Infof(format string, a ...interface{}) {
	if logLevel > 0 {
		message := paragraph(format, a...)
		pterm.Info.Println(message)
	}
}

func Question(text string) {
	pterm.Println()
	message := paragraph(text)
	pterm.FgMagenta.Println(message)
}

func Note(text string) {
	pterm.Println()
	message := paragraph(text)
	pterm.FgYellow.Println(message)
}

func HeaderInfof(format string, a ...interface{}) {
	message := fmt.Sprintf(format, a...)
	// Ensure the text is consistent for the header width
	padding := 85 - len(message)
	pterm.Println()
	pterm.DefaultHeader.
		WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
		WithTextStyle(pterm.NewStyle(pterm.FgLightWhite)).
		WithMargin(2).
		Printfln(message + strings.Repeat(" ", padding))
}

func paragraph(format string, a ...interface{}) string {
	return pterm.DefaultParagraph.WithMaxWidth(100).Sprintf(format, a...)
}
