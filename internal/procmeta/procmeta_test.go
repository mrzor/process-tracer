package procmeta

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnviron_Basic(t *testing.T) {
	raw := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"USER=testuser",
	}

	result := parseEnviron(raw)

	expected := map[string]string{
		"PATH": "/usr/bin:/bin",
		"HOME": "/home/user",
		"USER": "testuser",
	}

	assert.Equal(t, expected, result)
}

func TestParseEnviron_EmptyValue(t *testing.T) {
	raw := []string{
		"EMPTY_VAR=",
		"NORMAL_VAR=value",
	}

	result := parseEnviron(raw)

	assert.Len(t, result, 2)
	assert.Equal(t, "", result["EMPTY_VAR"])
	assert.Equal(t, "value", result["NORMAL_VAR"])
}

func TestParseEnviron_MultipleEquals(t *testing.T) {
	raw := []string{
		"DATABASE_URL=postgres://user:pass=123@localhost/db",
		"EQUATION=x=y=z",
	}

	result := parseEnviron(raw)

	assert.Len(t, result, 2)
	assert.Equal(t, "postgres://user:pass=123@localhost/db", result["DATABASE_URL"])
	assert.Equal(t, "x=y=z", result["EQUATION"])
}

func TestParseEnviron_DuplicateKeys(t *testing.T) {
	raw := []string{
		"KEY=value1",
		"KEY=value2",
		"KEY=value3",
	}

	result := parseEnviron(raw)

	assert.Len(t, result, 1)
	assert.Equal(t, "value3", result["KEY"], "last value should win")
}

func TestParseEnviron_MalformedEntries(t *testing.T) {
	raw := []string{
		"NOEQUALS",
		"=VALUE",
		"VALID=value",
		"",
		"ANOTHER_VALID=test",
	}

	result := parseEnviron(raw)

	assert.Len(t, result, 2, "only valid entries should be parsed")
	assert.Contains(t, result, "VALID")
	assert.Contains(t, result, "ANOTHER_VALID")
	assert.NotContains(t, result, "NOEQUALS")
	assert.NotContains(t, result, "")
}

func TestParseEnviron_Empty(t *testing.T) {
	result := parseEnviron([]string{})
	assert.Empty(t, result)
}

func TestParseEnviron_SpecialCharacters(t *testing.T) {
	raw := []string{
		"JSON={\"key\": \"value\"}",
		"WHITESPACE=  spaces  ",
		"NEWLINE=line1\nline2",
		"TAB=col1\tcol2",
	}

	result := parseEnviron(raw)

	assert.Len(t, result, 4)
	assert.Equal(t, "{\"key\": \"value\"}", result["JSON"])
	assert.Equal(t, "  spaces  ", result["WHITESPACE"])
	assert.Equal(t, "line1\nline2", result["NEWLINE"])
	assert.Equal(t, "col1\tcol2", result["TAB"])
}

func TestParseCmdline_Basic(t *testing.T) {
	raw := []string{"bash", "-c", "echo hello"}

	args, fullCmd := parseCmdline(raw)

	assert.Equal(t, []string{"bash", "-c", "echo hello"}, args)
	assert.Equal(t, "bash -c echo hello", fullCmd)
}

func TestParseCmdline_Empty(t *testing.T) {
	args, fullCmd := parseCmdline([]string{})

	assert.Empty(t, args)
	assert.Empty(t, fullCmd)
}

func TestParseCmdline_SingleArg(t *testing.T) {
	raw := []string{"/usr/bin/ls"}

	args, fullCmd := parseCmdline(raw)

	require.Len(t, args, 1)
	assert.Equal(t, "/usr/bin/ls", args[0])
	assert.Equal(t, "/usr/bin/ls", fullCmd)
}

func TestParseCmdline_WithSpaces(t *testing.T) {
	raw := []string{"python", "-c", "print('hello world')"}

	args, fullCmd := parseCmdline(raw)

	require.Len(t, args, 3)
	assert.Equal(t, "print('hello world')", args[2])
	assert.Equal(t, "python -c print('hello world')", fullCmd)
}

func TestParseCmdline_EmptyArgs(t *testing.T) {
	raw := []string{"cmd", "", "arg"}

	args, fullCmd := parseCmdline(raw)

	require.Len(t, args, 3)
	assert.Equal(t, "", args[1])
	assert.Equal(t, "cmd  arg", fullCmd)
}
