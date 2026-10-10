---
name: go-orm-injection-method
description: Go 数据访问层 SQL 注入审计方法：GORM 内联条件与原始片段、sqlx / database/sql 拼接、ORDER BY 等标识符。审计使用 GORM、sqlx、xorm 的 Go 项目的 SQL 注入时读取。
category: audit_method
scope: global
applies_to:
  languages: [go]
  vuln_classes: [sqli]
---
# Go ORM 注入要点

## GORM（v1 `jinzhu/gorm`、v2 `gorm.io/gorm`）
- **内联条件**：`db.First(&u, x)`、`db.Find(&u, x)`、`Take` / `Last` / `Delete(&u, x)` 的第二个参数：
  - 数字（`int`、`uint`）和数字切片按主键查询，安全。
  - **非数字字符串作为原始 SQL 条件**拼进 WHERE（`db.Find(&u, "1 = 1")` 返回全部记录）。v2 的 `Statement.BuildCondition` 对能 `strconv.Atoi` 的字符串仍按主键处理，其余只有一个字符串参数的条件生成 `clause.Expr{SQL: s}`；攻击者传入的非数字字符串因此成为 SQL。
  - 因此 `mux.Vars(r)["id"]`、`c.Param("id")`、`c.Query(...)` 等**未转成数字**的请求字符串直接作为内联条件 = SQL 注入，通常在鉴权之前执行，可布尔盲注读取整库；MySQL 连接开启 `multiStatements` 时可堆叠查询。
  - `db.First(&u, "id = ?", x)`（带占位符的条件 + 参数）安全。
- **原始片段**：`Where` / `Or` / `Not` / `Having` / `Joins` / `Group` 的第一个参数是 SQL 片段。
  - 用 `+` 或 `fmt.Sprintf` 拼接请求值 = 注入。
  - `db.Where("name = ?", n)`、`db.Where(&User{Name: n})`、`map[string]any{...}` 安全。
- **标识符**：`Order(col)`、`Select(cols)`、`Distinct(...)`、`Pluck(col, ...)`、`Table(name)` 的列名 / 表名不能参数化。
  - 请求中的排序字段、方向、列名必须走白名单。
  - `clause.OrderByColumn{Column: clause.Column{Name: x}}` 会给标识符加引号，但要确认所用方言的转义实现。
- **Raw / Exec**：`db.Raw(sql, args...)`、`db.Exec(sql, args...)` 的 sql 若拼接请求值即注入；`?` / `@name` 参数安全。
- **Scopes / 分页**：自定义 Scope 中拼接的 `Order` / `Limit` 字符串同样适用以上规则。

## database/sql、sqlx、xorm
- `Query` / `QueryRow` / `Exec` / `Get` / `Select` / `NamedExec` 的 SQL 字符串用 `+`、`Sprintf`、`strings.Join` 拼接请求值即注入；`$1` / `?` / `:name` 参数安全。
- `sqlx.In` 生成的占位符安全，但随后的 `Rebind` 必须使用其返回的 SQL。
- xorm：`Where(sql, args...)` 与 GORM 相同；`OrderBy(s)`、`SQL(s)` 拼接请求值即注入；`ID(x)` 按主键安全。

## 取证与判定
- 追到请求来源：路径参数、查询参数、表单、JSON 字段，以及是否经过 `strconv.Atoi` / `ParseInt` 转换。转成数字后即安全。
- 依赖源码不在快照中时，GORM 内联条件的语义以本条为准，不必因“读不到 gorm 源码”降为待确认；写明 GORM 版本（`go.mod`）。
- 影响写清：是否在鉴权前执行、能读取哪些表（如访问令牌、密码哈希），以及布尔 / 时间盲注的可观测差异。
