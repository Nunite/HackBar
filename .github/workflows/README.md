# GitHub Actions 工作流说明

本目录包含了 HackBar Burp 扩展的 CI/CD 工作流配置。

## 工作流文件

### 1. `gradle.yml` - 完整构建和测试工作流

**触发条件：**
- 推送到 `main` 或 `master` 分支
- 创建针对主分支的 Pull Request
- 手动触发

**功能：**
- 在多个 Java 版本（8, 11）上构建和测试
- 代码质量检查
- 生成构建报告
- 自动发布（当推送到主分支时）

**适用场景：**
- 正式发布前的完整验证
- Pull Request 的全面检查
- 确保多版本兼容性

### 2. `build.yml` - 快速构建工作流

**触发条件：**
- 推送到 `main`、`master` 或 `develop` 分支
- 创建针对主分支的 Pull Request

**功能：**
- 快速构建 JAR 文件
- 基于 Java 8（项目目标版本）
- 上传构建产物

**适用场景：**
- 日常开发的快速验证
- 获取最新的构建文件
- 开发分支的持续集成

## 使用方法

### 自动触发
工作流会在以下情况自动运行：
1. 当你推送代码到指定分支时
2. 当创建或更新 Pull Request 时

### 手动触发
1. 进入 GitHub 仓库的 "Actions" 页面
2. 选择要运行的工作流
3. 点击 "Run workflow" 按钮

### 下载构建产物
1. 进入 "Actions" 页面
2. 点击已完成的工作流运行
3. 在 "Artifacts" 部分下载生成的 JAR 文件

## 构建产物

- **hackbar-extension**: 快速构建生成的 JAR 文件
- **hackbar-jar-java-X**: 特定 Java 版本构建的 JAR 文件
- **hackbar-release**: 正式发布版本的 JAR 文件

## 注意事项

1. **Java 版本**: 项目主要针对 Java 8，但也会测试 Java 11 的兼容性
2. **Burp 扩展**: 生成的 JAR 文件可以直接加载到 Burp Suite 中
3. **依赖**: 项目使用 Burp Extender API 2.1
4. **构建时间**: 快速构建通常在 2-3 分钟内完成

## 故障排除

如果构建失败，请检查：
1. Java 代码语法错误
2. 依赖项问题
3. Gradle 配置问题
4. 查看构建日志获取详细错误信息