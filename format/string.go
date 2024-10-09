package format

import "strconv"

func ParseToInt(a string) int {
	result, _ := strconv.Atoi(a)
	return result
}

func ParseToString(a int) string {
	return strconv.Itoa(a)
}
