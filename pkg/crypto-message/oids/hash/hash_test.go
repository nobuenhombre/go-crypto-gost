package hash

import (
	"errors"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"reflect"
	"testing"
)

type getTest struct {
	in  oids.ID
	out Function
	err error
}

func getTestsGet() []getTest {
	return []getTest{
		{
			in:  oids.Tc26Gost34112012256,
			out: GostR34112012256,
			err: nil,
		},
		{
			in:  "GJFge7f3u3y6",
			out: UnknownHashFunction,
			err: &ge.NotFoundError{
				Key: "GJFge7f3u3y6",
			},
		},
	}
}

func TestGet(t *testing.T) {
	getTests := getTestsGet()

	for i := 0; i < len(getTests); i++ {
		test := &getTests[i]
		out, err := Get(test.in)

		outEqual := reflect.DeepEqual(out, test.out)
		errEqual := err == nil
		if test.err != nil {
			errEqual = errors.Is(err, test.err)
		}

		if !(outEqual && errEqual) {
			t.Errorf(
				"[i=%v], Get(%v), Expected (%v, %v) Actual (%v, %v)\n",
				i, test.in, test.out, test.err, out, err,
			)
		}
	}
}
