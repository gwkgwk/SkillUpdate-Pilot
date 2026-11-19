# 自研方法

主流程：hsda → behavior_graph → llm → decision。

sandbox / dynamic_verification 提供仅用于受控 Mock 的动态验证；marketplace / versioning 管理
来源与版本数据；evaluation 保留指标与分组统计。各模块 models.py 即当前运行接口。

B1–B7、消融、P8 重复占位契约和传统比较方法已移至项目外归档，当前包不再依赖这些代码。
