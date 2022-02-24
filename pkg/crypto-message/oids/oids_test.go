package oids

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"reflect"
	"testing"
)

type getIDTest struct {
	in  asn1.ObjectIdentifier
	out ID
	err error
}

func getTestsGetID() []getIDTest {
	return []getIDTest{
		{
			in:  asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2},
			out: Tc26Gost34112012256,
			err: nil,
		},
		{
			in:  asn1.ObjectIdentifier{9, 99, 999, 9999, 9, 99, 999, 9999},
			out: Unknown,
			err: &ge.NotFoundError{
				Key: fmt.Sprintf("%#v", asn1.ObjectIdentifier{9, 99, 999, 9999, 9, 99, 999, 9999}),
			},
		},
	}
}

func TestGetID(t *testing.T) {
	getIDTests := getTestsGetID()

	for i := 0; i < len(getIDTests); i++ {
		test := &getIDTests[i]
		out, err := GetID(test.in)

		var e *ge.IdentityError

		outEqual := reflect.DeepEqual(out, test.out)
		errEqual := err == nil
		if test.err != nil {
			errEqual = errors.As(err, &e) && reflect.DeepEqual(e.Parent, test.err)
		}

		if !(outEqual && errEqual) {
			t.Errorf(
				"[i=%v], GetID(%v), Expected (%v, %v) Actual (%v, %v)\n",
				i, test.in, test.out, test.err, out, err,
			)
		}
	}
}

type getTest struct {
	in  ID
	out asn1.ObjectIdentifier
	err error
}

func getTestsGet() []getTest {
	return []getTest{
		{
			in:  Tc26Gost34112012256,
			out: asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2},
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

		var e *ge.IdentityError

		outEqual := reflect.DeepEqual(out, test.out)
		errEqual := err == nil
		if test.err != nil {
			errEqual = errors.As(err, &e) && reflect.DeepEqual(e.Parent, test.err)
		}

		if !(outEqual && errEqual) {
			t.Errorf(
				"[i=%v], Get(%v), Expected (%v, %v) Actual (%v, %v)\n",
				i, test.in, test.out, test.err, out, err,
			)
		}
	}
}
