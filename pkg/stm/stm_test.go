package stm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStructToMap(t *testing.T) {
	assert := assert.New(t)

	type nested struct {
		D string `json:"d"`
		E int    `json:"e"`
		F bool   `json:"f"`
	}
	type mytype struct {
		A string `json:"a"`
		B int    `json:"b"`
		C bool   `json:"c"`
		nested
	}

	s := &mytype{
		A: "a",
		B: 1,
		C: true,
		nested: nested{
			D: "d",
			E: 2,
			F: false,
		},
	}
	m := make(map[string]interface{})
	err := StructToMap(s, &m)
	assert.NoError(err)
	assert.Equal("a", m["a"])
	assert.Equal(float64(1), m["b"])
	assert.Equal(true, m["c"])
	assert.Equal("d", m["d"])
	assert.Equal(float64(2), m["e"])
	assert.Equal(false, m["f"])
}

func TestMapToStruct(t *testing.T) {
	assert := assert.New(t)

	type nested struct {
		D string `json:"d"`
		E int    `json:"e"`
		F bool   `json:"f"`
	}
	type mytype struct {
		A string `json:"a"`
		B int    `json:"b"`
		C bool   `json:"c"`
		nested
	}

	m := map[string]interface{}{
		"a": "a",
		"b": 1,
		"c": true,
		"d": "d",
		"e": 2,
		"f": false,
	}

	var s mytype
	err := MapToStruct(m, &s)
	assert.NoError(err)
	assert.Equal("a", s.A)
	assert.Equal(1, s.B)
	assert.Equal(true, s.C)
	assert.Equal("d", s.nested.D)
	assert.Equal(2, s.nested.E)
	assert.Equal(false, s.nested.F)
}
