---
name: deserialization-method
description: 反序列化审计方法：Java 原生反序列化、Jackson/Fastjson 多态类型、XStream、SnakeYAML，Go gob/yaml。审计处理外部序列化数据的代码时读取。
category: audit_method
scope: global
applies_to:
  vuln_classes: [deserialization, code_injection]
---
# 反序列化判断要点

## 先确认数据是否外部可控
- 入口：HTTP 请求体、Cookie、消息队列消息、RPC 参数、缓存（Redis 中由其他服务写入的值）、文件上传。
- 只反序列化本服务自己写入、且写入方不可被外部影响的数据，一般不构成漏洞；需要写明依据。

## Java
- **原生反序列化**：`ObjectInputStream.readObject`、`readUnshared`，以及封装它的工具（`SerializationUtils.deserialize`、RMI、JMX、部分 RPC 框架的 Java 序列化协议）。外部可控即高危；防护为 `ObjectInputFilter`（JEP 290）白名单或不使用原生序列化。
- **Jackson**：`ObjectMapper.enableDefaultTyping()` / `activateDefaultTyping(...)` 开启全局多态，或字段上 `@JsonTypeInfo(use = Id.CLASS / Id.MINIMAL_CLASS)`，且目标类型是 `Object`、`Serializable` 等宽泛类型时可被利用；`Id.NAME` 配合显式 `@JsonSubTypes` 是安全写法。检查 `PolymorphicTypeValidator` 是否限制了基类。
- **Fastjson 1.x**：`JSON.parseObject(text)` / `parse(text)` 在 `autoType` 开启（`ParserConfig.getGlobalInstance().setAutoTypeSupport(true)` 或 `addAccept` 过宽）时高危；版本低于 1.2.83 即使未显式开启也有已知绕过，需结合依赖版本判断；`safeMode` 开启可视为防护。
- **XStream**：`fromXML` 未调用 `allowTypes` / `addPermission` 限制类型时高危（1.4.18 起默认白名单，需看版本）。
- **SnakeYAML**：`new Yaml().load(input)`（1.x 默认构造器）可实例化任意类；`new Yaml(new SafeConstructor(...))` 或 2.x 默认的受限构造器是安全写法。

## Go
- `encoding/gob`、`encoding/json` 本身不会执行任意代码，风险主要在解码到 `interface{}` 后被当作可信结构使用（类型混淆、越权字段注入）。
- `gopkg.in/yaml.v2/v3` 解码大文档可导致资源耗尽（别名膨胀，“billion laughs”）；关注是否限制输入大小。

## 结论要求
- 成立需要写明：可控输入 → 反序列化调用 → 危险配置或版本。仅有反序列化调用、没有可控输入或危险配置时，不应判为漏洞。
- 依赖版本决定是否有已知利用链时，引用构建文件中的版本声明作为证据。
