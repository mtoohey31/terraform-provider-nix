package nix

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

func TestReportErrorWithTitle(t *testing.T) {
	assert.False(t, reportErrorWithTitle(nil, "", nil))

	actualDiagnostics := diag.Diagnostics{}
	assert.True(t, reportErrorWithTitle(assert.AnError, "Test Error Title", &actualDiagnostics))

	expectedDiagnostics := diag.Diagnostics{}
	expectedDiagnostics.AddError("Test Error Title", assert.AnError.Error())
	assert.Equal(t, expectedDiagnostics, actualDiagnostics)
}
