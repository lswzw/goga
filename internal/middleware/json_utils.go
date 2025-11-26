// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

// findJSONEnd 查找 JSON 对象的结束位置
// 返回匹配的 '}' 字符的索引位置，如果没找到返回 -1
func findJSONEnd(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	// 跳过前导空白字符
	start := 0
	for start < len(data) && (data[start] == ' ' || data[start] == '\t' || data[start] == '\n' || data[start] == '\r') {
		start++
	}

	if start >= len(data) || data[start] != '{' {
		return -1
	}

	// 使用简单的计数器来匹配大括号
	braceCount := 0
	inString := false
	escaped := false

	for i := start; i < len(data); i++ {
		c := data[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if c == '"' && !escaped {
			inString = !inString
			continue
		}

		if !inString {
			if c == '{' {
				braceCount++
			} else if c == '}' {
				braceCount--
				if braceCount == 0 {
					return i
				}
			}
		}
	}

	return -1
}
