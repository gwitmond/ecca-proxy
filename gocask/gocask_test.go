package gocask

import (
	"os"
	"testing"
)

func TestNewGocask(t *testing.T) {

	gocask, err := NewGocask("testkv")
	defer os.RemoveAll("testkv")

	if err != nil {
		t.Errorf("Error \"%q\" while opening directory \"%q\"", err.Error(), "testkv")
	}

	err = gocask.Close()

	if err != nil {
		t.Errorf("Error \"%q\" while closing casket", err.Error())
	}
}

func TestPut(t *testing.T) {
	var gocask *Gocask
	var err error
	gocask, err = NewGocask("testkv")
	defer os.RemoveAll("testkv")

	if err != nil {
		t.Errorf("Error \"%q\" while opening directory \"%q\"", err.Error(), "testkv")
	}

	key := "key 1"
	value := []byte("value 1")
	err = gocask.Put(key, value)

	if err != nil {
		t.Errorf("Error \"%q\" while puting the key: \"%q\" with value: \"%q\"", err.Error(), key, value)
	}

	key = "Unicode key: 世界"
	value = []byte("Unicode value 世界")

	err = gocask.Put(key, value)

	if err != nil {
		t.Errorf("Error \"%q\" while puting the key: \"%q\" with value: \"%q\"", err.Error(), key, value)
	}

	if len(gocask.keydir.keys) != 2 {
		t.Errorf("Keydir has %d keys, shoud have %d", len(gocask.keydir.keys), 2)
	}

	err = gocask.Close()

	if err != nil {
		t.Errorf("Error \"%q\" while closing the store", err.Error())
	}
}

type TestKeyValue struct {
	key      string
	value    []byte
	ksz, vsz int32
}

func TestGet(t *testing.T) {

	var gocask *Gocask
	var err error

	gocask, err = NewGocask("testkv")
	defer os.RemoveAll("testkv")

	var readvalue []byte

	testdata := []TestKeyValue{
		TestKeyValue{"key1", []byte("value1"), 4, 6},
		TestKeyValue{"key2", []byte("value2"), 4, 6},
	}

	for _, kv := range testdata {
		gocask.Put(kv.key, kv.value)
		readvalue, err = gocask.Get(kv.key)
		if err != nil {
			t.Errorf("Error while calling get on old gocask. %q", err.Error())
			return
		}

		if string(readvalue) != string(kv.value) {
			t.Errorf("Exptected %q got %q", string(kv.value), string(readvalue))
			return
		}

		t.Logf("For key %q got %q", kv.key, string(readvalue))
	}

	gocask.Close()

	gocask, err = NewGocask("testkv")

	for _, kv := range testdata {
		gocask.Put(kv.key, kv.value)
		readvalue, err = gocask.Get(kv.key)
		if err != nil {
			t.Errorf("Error while calling get on old gocask. %q", err.Error())
			return
		}

		if string(readvalue) != string(kv.value) {
			t.Errorf("Exptected %q got %q", string(kv.value), string(readvalue))
			return
		}

		t.Logf("For key %q got %q", kv.key, string(readvalue))
	}

	gocask.Close()
}
