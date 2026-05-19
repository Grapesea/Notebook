### 探险模式

SQL-I-1

> ```sql
> Input: 
> Person table:
> +----------+----------+-----------+
> | personId | lastName | firstName |
> +----------+----------+-----------+
> | 1        | Wang     | Allen     |
> | 2        | Alice    | Bob       |
> +----------+----------+-----------+
> Address table:
> +-----------+----------+---------------+------------+
> | addressId | personId | city          | state      |
> +-----------+----------+---------------+------------+
> | 1         | 2        | New York City | New York   |
> | 2         | 3        | Leetcode      | California |
> +-----------+----------+---------------+------------+
> Output: 
> +-----------+----------+---------------+----------+
> | firstName | lastName | city          | state    |
> +-----------+----------+---------------+----------+
> | Allen     | Wang     | Null          | Null     |
> | Bob       | Alice    | New York City | New York |
> +-----------+----------+---------------+----------+
> ```
>
> Explanation: 
> There is no address in the address table for the personId = 1 so we return null in their city and state.
> addressId = 1 contains information about the address of personId = 2.

原来真是left join，这下是基础不扎实了.

* INNER JOIN（即 `join`）：只返回**两张表中都能匹配上**的行。如果 Person 表中某人在 Address 表里没有对应记录，这个人就会被**直接丢弃**，不出现在结果里。

* LEFT JOIN：以**左表（Person）为基准**，左表的每一行都会出现在结果中。如果右表（Address）里找不到匹配的行，右表的字段就用 `NULL` 填充。

于是答案：

```sql
select p.firstName, p.lastName, a.city, a.state from Person p left join Address a
on p.personId = a.personId;
```

这样output就可以有null出现了.

---

SQL-I-3

```sql
select * from (select * from Cinema 
    where id % 2 = 1 and description <> "boring"
) new
order by rating desc;
```

---

SQL I-4

> Table: `Customer`
>
> ```
> +-------------+---------+
> | Column Name | Type    |
> +-------------+---------+
> | id          | int     |
> | name        | varchar |
> | referee_id  | int     |
> +-------------+---------+
> In SQL, id is the primary key column for this table.
> Each row of this table indicates the id of a customer, their name, and the id of the customer who referred them.
> ```
>
> Find the names of the customer that are either:
>
> 1. **referred by** any customer with `id != 2`.
> 2. **not referred by** any customer.
>
> Return the result table in **any order**.
>
> The result format is in the following example.
>
> **Example 1:**
>
> ```
> Input: 
> Customer table:
> +----+------+------------+
> | id | name | referee_id |
> +----+------+------------+
> | 1  | Will | null       |
> | 2  | Jane | null       |
> | 3  | Alex | 2          |
> | 4  | Bill | null       |
> | 5  | Zack | 1          |
> | 6  | Mark | 2          |
> +----+------+------------+
> Output: 
> +------+
> | name |
> +------+
> | Will |
> | Jane |
> | Bill |
> | Zack |
> +------+
> ```

安全取反判断：

```sql
select name from customer where not referee_id <=> 2;
```

或者可以：

```sql
SELECT name FROM customer WHERE referee_id != 2 OR referee_id IS NULL;
```

其原因在于，SQL中bool不止True, False，还有Unknown，所以`IS NULL`和`IS NOT NULL`需要分别处理.

---

SQL II-1

> Table: `Orders`
>
> ```
> +-----------------+----------+
> | Column Name     | Type     |
> +-----------------+----------+
> | order_number    | int      |
> | customer_number | int      |
> +-----------------+----------+
> order_number is the primary key (column with unique values) for this table.
> This table contains information about the order ID and the customer ID.
> ```
>
>  Write a solution to find the `customer_number` for the customer who has placed the largest number of orders. The test cases are generated so that exactly one customer will have placed more orders than any other customer. The result format is in the following example.  Example 1:
>
> ```
> Input: 
> Orders table:
> +--------------+-----------------+
> | order_number | customer_number |
> +--------------+-----------------+
> | 1            | 1               |
> | 2            | 2               |
> | 3            | 3               |
> | 4            | 3               |
> +--------------+-----------------+
> Output: 
> +-----------------+
> | customer_number |
> +-----------------+
> | 3               |
> +-----------------+
> Explanation: 
> The customer with number 3 has two orders, which is greater than either customer 1 or 2 because each of them only has one order. 
> So the result is customer_number 3.
> ```

用`group by`最方便：

```sql
select customer_number from Orders
group by customer_number
order by count(order_number) desc
limit 1;
```

---

SQL II-2

```sql
select class from Courses group by class
having count(student) >= 5;
```

having语句学会就行.

---

SQL II-3

三目运算符和日期函数：

```sql
select date_format(trans_date, '%Y-%m') as month,
        country,
        count(*) as trans_count,
        count(if(state = 'approved', 1, NULL)) as approved_count,
        sum(amount) as trans_total_amount,
        sum(if(state='approved', amount, 0)) as approved_total_amount
        from transactions
    group by month, country
```

注意：

`%Y-%M`跟`%Y-%m`结果不一样，前者是`December`形式，后者是`01-12`的形式.

---

