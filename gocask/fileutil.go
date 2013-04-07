package gocask

import (
	"bufio"
	"bytes"
	"os"
)

/*
	Print the data in raw format with the given label.
	Useful only for debug.
*/
func debugPrint(label string, data interface{}) {
	print("\n")
	print(label)
	print(": ")
	print(data)
}

/*
   Return true if the given path exists and points to a valid file.
   If the file is symlink follows the symlink
*/
func fileExists(filename string) bool {
	file, err := os.Stat(filename)
	if err != nil {
		return false
	}

	return !file.IsDir()
}

/*
	Convert the given byte buffer using the default Go encoding (utf-8)
*/
func ConvertToString(buff []byte) string {
	str, _ := (bufio.NewReader(bytes.NewBuffer(buff))).ReadString(byte(0))
	return str
}
