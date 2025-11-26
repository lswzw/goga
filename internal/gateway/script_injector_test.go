// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"io"
	"strings"
	"testing"
)

// runTest 是一个辅助函数，用于以流式方式运行注入器测试。
func runTest(t *testing.T, name, input, script, expected string) {
	t.Run(name, func(t *testing.T) {
		reader := strings.NewReader(input)
		injector := NewScriptInjector(reader, []byte(script))
		defer injector.Close()

		var resultBuilder strings.Builder
		
		// 使用 io.Copy 来模拟真实世界的读取循环
		_, err := io.Copy(&resultBuilder, injector)
		if err != nil {
			t.Fatalf("读取时发生意外错误: %v", err)
		}

		if resultBuilder.String() != expected {
			t.Errorf("注入结果不匹配。\n预期: %q\n得到:      %q", expected, resultBuilder.String())
		}
	})
}

func TestScriptInjector(t *testing.T) {
	// 1. 基本情况：简单注入
	runTest(t, "BasicInjection",
		`<html><head></head><body>Content here</body></html>`,
		`<script>alert("injected");</script>`,
		`<html><head></head><body>Content here<script>alert("injected");</script></body></html>`,
	)

	// 2. 未找到标签：应返回原始内容
	runTest(t, "NoTagFound",
		`<html><head></head><body>Content here</html>`,
		`<script>alert("injected");</script>`,
		`<html><head></head><body>Content here</html>`,
	)

	// 3. 标签在开头
	runTest(t, "TagAtStart",
		`</body></html>`,
		`<script/>`,
		`<script/></body></html>`,
	)

	// 4. 标签在块边界处
	// runTest 中的小缓冲区将强制触发此条件。
	runTest(t, "TagAtBoundary",
		`long prefixxxxxxxxx`+`</body>`+`long suffixxxxxxxxxx`,
		`<s/>`,
		`long prefixxxxxxxxx<s/></body>long suffixxxxxxxxxx`,
	)

	// 5. 空输入流
	runTest(t, "EmptyInput",
		"",
		"<script/>",
		"",
	)

	// 6. 空脚本：不应有任何操作
	runTest(t, "EmptyScript",
		`<html><body></body></html>`,
		"",
		`<html><body></body></html>`,
	)

	// 7. 大输入以测试缓冲区循环
	prefix := strings.Repeat("a", 10000)
	suffix := strings.Repeat("b", 10000)
	runTest(t, "LargeInput",
		prefix+`<body>`+suffix+`</body>`,
		`<script/>`,
		prefix+`<body>`+suffix+`<script/></body>`,
	)
}