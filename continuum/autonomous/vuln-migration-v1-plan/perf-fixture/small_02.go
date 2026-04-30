package small02

import (
    "fmt"
    "strings"
)

// Format builds a key=value pair string.
func Format02(k, v string) string {
    return fmt.Sprintf("%s=%s", strings.TrimSpace(k), strings.TrimSpace(v))
}

// Parse splits a key=value pair.
func Parse02(s string) (string, string) {
    parts := strings.SplitN(s, "=", 2)
    if len(parts) != 2 {
        return s, ""
    }
    return parts[0], parts[1]
}
