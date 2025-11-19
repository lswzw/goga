# GoGa 客户端加密脚本

此目录包含用于客户端加密的 JavaScript 文件。

## 文件说明

- `goga-crypto.js`: 这是 **开发源文件**，包含了完整注释和日志，易于阅读和维护。所有未来的功能修改和逻辑调整都应在此文件上进行。

- `goga-crypto.min.js`: 这是 **生产文件**，是 `goga-crypto.js` 经过压缩和混淆后的版本。此文件的体积更小、执行效率更高且难以阅读，能起到保护代码的作用。**请勿直接编辑此文件**。最终应由网关向用户提供这个文件。

## 如何生成生产文件

当您修改了 `goga-crypto.js` 之后，您必须运行以下命令来重新生成 `goga-crypto.min.js` 文件。

**前置要求**: 您需要安装 [Node.js](https://nodejs.org/) 环境，以便能使用 `npx` 命令。

在项目的根目录下执行以下命令：

```bash
npx terser static/goga-crypto.js -o static/goga-crypto.min.js -c drop_console=true -m
```

### 命令详解

- `npx terser`: 使用 npx 来运行 `terser` 包，无需全局安装。
- `static/goga-crypto.js`: 指定输入的源文件。
- `-o static/goga-crypto.min.js`: 指定输出的目标文件。
- `-c drop_console=true`: 压缩代码，并移除所有 `console.*` 的日志输出。
- `-m`: 混淆代码，将变量名和函数名等替换为短小的无意义名称。
