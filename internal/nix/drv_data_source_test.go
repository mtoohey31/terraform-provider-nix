//go:generate go build -o testdata/mock_nix_build_bin/nix testdata/mock_nix_build.go

package nix

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDrvDataSource_Read(t *testing.T) {
	const (
		testFlakeRef = "test/flake#ref"
		testOutPath  = "/nix/store/test-out-path"
	)

	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Setenv("PATH", filepath.Join(wd, "testdata", "mock_nix_build_bin"))

	var schemaResp datasource.SchemaResponse
	drvDataSource{}.Schema(nil, datasource.SchemaRequest{}, &schemaResp)
	require.Empty(t, schemaResp.Diagnostics)

	tests := []struct {
		description string

		config tfsdk.Config
		env    map[string]string

		expectedResp datasource.ReadResponse
	}{
		{
			description: "happy path",
			config: tfsdk.Config{
				Raw: tftypes.NewValue(tftypes.Object{}, map[string]tftypes.Value{
					"flake_ref": tftypes.NewValue(tftypes.String, testFlakeRef),
					"out_path":  tftypes.NewValue(tftypes.String, nil),
				}),
				Schema: schemaResp.Schema,
			},
			env: map[string]string{
				"MOCK_NIX_BUILD_EXPECTED_FLAKE_REF": testFlakeRef,
				"MOCK_NIX_BUILD_STDOUT":             testOutPath + "\n",
			},
			expectedResp: datasource.ReadResponse{
				State: tfsdk.State{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"flake_ref": tftypes.String,
							"out_path":  tftypes.String,
						},
					}, map[string]tftypes.Value{
						"flake_ref": tftypes.NewValue(tftypes.String, testFlakeRef),
						"out_path":  tftypes.NewValue(tftypes.String, testOutPath),
					}),
					Schema: schemaResp.Schema,
				},
			},
		},

		{
			description: "non-zero exit code",
			config: tfsdk.Config{
				Raw: tftypes.NewValue(tftypes.Object{}, map[string]tftypes.Value{
					"flake_ref": tftypes.NewValue(tftypes.String, testFlakeRef),
					"out_path":  tftypes.NewValue(tftypes.String, nil),
				}),
				Schema: schemaResp.Schema,
			},
			env: map[string]string{
				"MOCK_NIX_BUILD_EXPECTED_FLAKE_REF": testFlakeRef,
				"MOCK_NIX_BUILD_STDOUT":             "something went wrong\n",
				"MOCK_NIX_BUILD_STDERR":             "something went wrong\n",
				"MOCK_NIX_BUILD_EXIT_CODE":          "2",
			},
			expectedResp: datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Failed to Build Derivation",
						"exit status 2; `nix build` output:\nsomething went wrong\nsomething went wrong\n",
					),
				},
			},
		},
		{
			description: "no out paths",
			config: tfsdk.Config{
				Raw: tftypes.NewValue(tftypes.Object{}, map[string]tftypes.Value{
					"flake_ref": tftypes.NewValue(tftypes.String, testFlakeRef),
					"out_path":  tftypes.NewValue(tftypes.String, nil),
				}),
				Schema: schemaResp.Schema,
			},
			env: map[string]string{
				"MOCK_NIX_BUILD_EXPECTED_FLAKE_REF": testFlakeRef,
				"MOCK_NIX_BUILD_STDOUT":             "",
			},
			expectedResp: datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Derivation Produced No Outputs",
						"Derivation produced no outputs; `nix build` output:\n",
					),
				},
			},
		},
		{
			description: "multiple out paths",
			config: tfsdk.Config{
				Raw: tftypes.NewValue(tftypes.Object{}, map[string]tftypes.Value{
					"flake_ref": tftypes.NewValue(tftypes.String, testFlakeRef),
					"out_path":  tftypes.NewValue(tftypes.String, nil),
				}),
				Schema: schemaResp.Schema,
			},
			env: map[string]string{
				"MOCK_NIX_BUILD_EXPECTED_FLAKE_REF": testFlakeRef,
				"MOCK_NIX_BUILD_STDOUT":             "foo\nbar\nbaz\n",
			},
			expectedResp: datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Derivation Produced More Than One Output",
						"Derivation produced more than one output; `nix build` output:\nfoo\nbar\nbaz\n",
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			actualResp := datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
			}

			drvDataSource{}.Read(context.Background(), datasource.ReadRequest{
				Config: test.config,
				ProviderMeta: tfsdk.Config{
					Raw:    tftypes.NewValue(tftypes.Object{}, map[string]tftypes.Value{}),
					Schema: schema.Schema{},
				},
			}, &actualResp)

			assert.Equal(t, test.expectedResp, actualResp)
		})
	}
}
