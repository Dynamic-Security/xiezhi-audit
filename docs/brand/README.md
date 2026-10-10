# 獬豸 xiezhi-audit 品牌素材

## 图形

“角破环”：圆环代表被审计的系统，獬豸的独角从环内刺穿出去，环在穿出处断开——“触不直者去之”，找到并指出问题。

| 文件 | 用途 |
| --- | --- |
| `xiezhi-mark-dark.svg` | 主图标（墨色底），应用图标、头像 |
| `xiezhi-mark-light.svg` | 浅色底图标 |
| `xiezhi-lockup-dark.svg` / `xiezhi-lockup-light.svg` | 横版组合：图标 + “獬豸” + `xiezhi audit` |
| `xiezhi-lockup-tagline-dark.svg` / `xiezhi-lockup-tagline-light.svg` | 横版组合加标语“触不直者去之”与英文说明 |

产品中的使用：`apps/web/public/favicon.svg`（墨色底，圆环线宽加粗到 9，16 像素下仍清楚）、`apps/web/src/shared/ui/brand.tsx` 的 `BrandMark`（侧栏、登录页）。

## 颜色

| 名称 | 深色版 | 浅色版 |
| --- | --- | --- |
| 底色 | 墨 `#1F1C19` | 纸 `#F4EFE6`（描边 `#D9D1C3`） |
| 圆环 / 字 | 米白 `#F2EDE4` | 墨 `#1F1C19` |
| 角 / 副标题 | 琥珀 `#D9973A` | 深琥珀 `#B87418`（保证浅底对比度） |

## 注意
- 横版组合中的文字是 SVG `<text>`，显示依赖本机字体（宋体：Songti SC / Noto Serif SC / Source Han Serif SC）。正式对外使用前应换成可商用字体并转曲，或定制“獬豸”字标。
- 图标最小使用尺寸 16 像素；小于 32 像素时用加粗的圆环（favicon 与 `BrandMark` 已处理）。
