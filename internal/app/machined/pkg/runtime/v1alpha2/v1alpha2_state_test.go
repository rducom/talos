// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package v1alpha2_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/app/machined/pkg/runtime/v1alpha2"
)

// TestResourceDefinitions checks that every resource type declared in pkg/machinery/resources has a definition in the state,
// without which talosctl reports the resource as not registered.
func TestResourceDefinitions(t *testing.T) {
	st, err := v1alpha2.NewState()
	require.NoError(t, err)

	definitions, err := safe.StateListAll[*meta.ResourceDefinition](t.Context(), st.Resources())
	require.NoError(t, err)

	registered := map[string]struct{}{}

	for definition := range definitions.All() {
		registered[string(definition.TypedSpec().Type)] = struct{}{}
	}

	fset := token.NewFileSet()

	require.NoError(t, filepath.WalkDir(filepath.Join("..", "..", "..", "..", "..", "..", "pkg", "machinery", "resources"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}

		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Type" {
				return true
			}

			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}

			if typ := strings.Trim(lit.Value, "\"`"); !strings.HasPrefix(typ, "ResourceDefinitions.") {
				_, ok := registered[typ]
				assert.True(t, ok, "%s: %s is not registered in the state", path, typ)
			}

			return true
		})

		return nil
	}))
}
