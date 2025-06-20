# Project 模块说明

## 📁 目录结构

```
api/project/
├── __init__.py              # 路由注册
├── project.py               # 项目CRUD API接口 (13KB)
├── handler.py               # 项目业务逻辑处理 (15KB)
└── aggregation.py           # 项目数据聚合统计 (9.7KB)
```

## 🔄 文件职责分工

### 📋 project.py - 项目核心API
- **查询接口**: 项目列表、详情、统计
- **CRUD操作**: 创建、更新、删除项目
- **文件上传**: 批量扫描结果导入
- **路由定义**: `/project/*` 接口

### ⚙️ handler.py - 业务逻辑层
- **项目管理**: 项目资产分配和更新
- **数据处理**: 扫描结果解析和入库
- **辅助函数**: 
  - `update_project_count()` - 资产数量统计
  - `process_project_target_list()` - 目标处理
  - `parse_uploaded_file()` - 文件解析
  - `process_scan_results()` - 结果处理

### 📊 aggregation.py - 数据聚合层
- **统计分析**: 漏洞分布、资产数量
- **数据聚合**: 子域名、端口、服务聚合
- **路由定义**: `/project_aggregation/*` 接口

## 🔧 优化成果

1. **代码分层清晰**: API层、业务层、聚合层分离
2. **函数职责明确**: 辅助函数集中到handler.py
3. **减少代码重复**: 统一的工具函数复用
4. **提高可维护性**: 模块化设计便于扩展

## 📝 路由配置

```
/api/project/
├── /project/* (项目CRUD)
└── /project_aggregation/* (数据聚合)
```

所有路由通过 `__init__.py` 统一注册到main.py中 