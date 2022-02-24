package curves

import (
	"errors"
	"reflect"
	"testing"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type getTest struct {
	in  oids.ID
	out *gost3410.Curve
	err error
}

func getTestsGet() []getTest {
	return []getTest{
		{
			in:  oids.GostR34102001CryptoProAParamSet,
			out: gost3410.CurveIdGostR34102001CryptoProAParamSet(),
			err: nil,
		},
		{
			in:  "GJFge7f3u3y6",
			out: nil,
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
