package util

import "fmt"


func ThrowErrIfEmpty(str string, errText string) (error) {
	if str == "" {
		return fmt.Errorf("%s", errText)
	}
	return nil 
}
