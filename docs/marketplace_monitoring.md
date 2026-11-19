# P16 公开市场版本监测

第一阶段实现本地 Git 历史重建。第二阶段周期监测尚未启用；当前不发起网络请求，不下载或执行 Skill。

## 模块接口

| 模块 | 输入 → 输出 |
|---|---|
| MarketplaceCollector | 归档 listing JSON → MarketplaceListing（证据摘要、采集时间） |
| RepositoryResolver | listing → 仓库 URL、SkillPath、来源可信状态 |
| SkillIdentityManager | HTTPS Repository + SkillPath → 稳定 skill_id |
| GitHistory / Version Resolver | 本地完整 Git 仓库 + 完整 head SHA → first-parent 有序 commit |
| SnapshotManager | identity + commit → 全目录对象快照与逐文件 SHA256 |
| UpdateEventDetector | 旧/新快照 → 新增、删除、修改、唯一精确重命名 |
| MetadataDatabase | identity/snapshot/event/alert/review → SQLite 持久记录 |

所有模型定义于 marketplace/models.py。首次观察 INITIAL 无旧版本；删除 REMOVED 保存旧快照；
重新出现 REINTRODUCED 不跨缺失区间配对。commit_time 来自 Git，collected_at/discovered_at 是采集时间，
两者不可混为真实市场发布时间。无 Skill 变化的 commit 仍可保存快照，不生成更新事件。

身份基于规范 HTTPS 仓库 URL 与路径，不基于 Skill 名称。去掉 URL 尾部 .git 和斜杠，不自动合并 URL 别名、
仓库 fork、不同 owner 或迁移。调用者传入的仓库来源只是声明，离线无法验证其与远端一致，保留 UNVERIFIED。
相同目录摘要只形成 COPY_OR_MIGRATION_CANDIDATE，人工确认也需要额外来源证据才能决定迁移关系；
候选不会合并 Skill 身份或建立跨仓版本边。

## 快照与安全

通过 git ls-tree/cat-file 读取对象，不 checkout、不触发 filters/hooks、不 import Skill。二进制原样保存于
blobs/<sha256>，每个快照 manifest 保存所有相对路径、Git mode、Git OID、SHA256、字节数。
原始目录可从 manifest 与 blob 完整恢复为数据；symlink 保存链接文本，不跟随；gitlink/submodule 不拉取，
明确标记 incomplete；Git LFS 指针同样标记资源未展开，不拉取内容。上限 1024 文件、16 MiB，超出拒绝，
shallow repository 拒绝，不静默截断历史。不完整快照不参与复制/迁移候选匹配。
first-parent 只描述所选分支主线，merge 会比较合并前后树，不宣称重建全部分支发布历史。

SQLite records 保留首次记录，sightings 追加采集记录。相同事件重建幂等。风险告警必须有 event_id 与来源
证据；alert() 返回 PENDING 与 review_entry。review() 追加 reviewer、verdict、note、reviewed_at，
支持 CONFIRMED/REJECTED/UNCERTAIN。版本变化本身不触发恶意判定。

## 离线命令

```bash
python scripts/reconstruct_skill_history.py \
  --repository /path/to/local/repository \
  --repository-url https://github.com/owner/repository \
  --skill-path skills/example --head-sha FULL_COMMIT_SHA \
  --output-root artifacts/raw/marketplace/run-001
```

listing 归档输入为数组：marketplace、listing_url、repository_url、skill_path；SkillsMP/GitHub/其他市场
统一进入归档接口。归档摘要和时间保留，但不能把归档声明当作真实远端校验。

## 第二阶段设计

周期调度器按市场保存 cursor/ETag/last_success、请求预算和 next_allowed_at；collector 遵守官方 API、
公开访问规则、Retry-After 和限流响应，失败指数退避，不绕过鉴权或反爬。resolver 保存实际 API 证据，
验证 repo/path/commit 后才升级 VERIFIED；拉取只更新 Git 对象，不执行内容。周期实现前需确定实际 API
端点、访问规则与账户额度。当前阶段没有实现实时 SkillsMP/GitHub crawler 或定时任务。

持续监测指标需独立审核分母：Update Discovery Recall=检出的审核更新/全部审核更新；Version Pairing
Accuracy=正确配对/审核配对；Source Resolution Accuracy=正确来源/审核来源；Detection Delay 使用可信
公开时间至发现时间；Duplicate Rate=重复事件/全部发现；Alert Confirmation Rate=确认告警/已复核告警，
另报待审核率。没有 GT 或可信发布时间时输出 UNKNOWN，不以 commit timestamp 冒充发现延迟基准。
