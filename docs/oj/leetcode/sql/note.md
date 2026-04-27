## Leetcode MySQL

> 免费的一共105题，争取刷干净

176.找出第二高的薪水，没有就返回NULL

普通方法：

```sql
SELECT DISTINCT salary AS SecondHighestSalary FROM Employee
ORDER BY salary DESC LIMIT 1 OFFSET 1
```

上面的是错的，因为没有办法在记录不存在的时候返回NULL.

正确：将其作为子查询，这样能返回NULL.

```sql
SELECT (
SELECT DISTINCT salary FROM Employee
ORDER BY salary DESC LIMIT 1 OFFSET 1
)  AS SecondHighestSalary;
```

子查询：让找到的比最大的小，但是在剩余中最大

```sql
SELECT max(salary) AS SecondHighestSalary 
FROM Employee 
WHERE salary < (SELECT max(salary) FROM Employee);
```

---

177.Nth Highest Salary

在SQL中使用函数.

```sql
CREATE FUNCTION getNthHighestSalary(N INT) RETURN INT
BEGIN 
	DECLARE M INT; #声明局部变量并赋值
	SET M = N-1;
  RETURN (
  	SELECT DISTINCT salary FROM Employee
    ORDER BY salary DESC
    LIMIT M,1 # 偏移量为N-1，取1条
  );
END
```

---

178.Rank Scores

排名窗口函数：`RANK()`, `DENSE_RANK()`

 ```sql
 SELECT S.score,
 	DENSE_ARNK() OVER(
     	ORDER BY
         	S.Score DESC
         AS 'rank'
     )
     FROM Scores S;
 ```

---

180.连续三天登录

```sql
select distinct l1.num as ConsecutiveNums 
from Logs l1, Logs l2, Logs l3
where l1.id = l2.id-1 and l2.id = l3.id-1 and l1.num = l2.num and l2.num = l3.num;
```

---

181.easy

```sql
select e1.name as Employee from Employee e1, Employee e2 where e1.managerId = e2.id and e1.salary > e2.salary
```

---

182.easy

```sql
select email as Email from Person group by email
having COUNT(email) > 1
```

---

183.easy，用子查询

```sql
select name as Customers from Customers
where Customers.id not in (select customerId from Orders);
```

法二：用left join筛选：

```sql
SELECT name AS 'Customers'
FROM Customers
LEFT JOIN Orders ON Customers.Id = Orders.CustomerId
WHERE Orders.CustomerId IS NULL
```

---

184.有点麻烦

先创建一个子表：

```sql
SELECT
    DepartmentId, MAX(Salary)
FROM
    Employee
GROUP BY DepartmentId;
```

获得了：

| DepartmentId | MAX(Salary) |
| ------------ | ----------- |
| 1            | 90000       |
| 2            | 80000       |

然后使用join连接进行直接查询：

```sql
SELECT
    d.name AS 'Department',
    e.name AS 'Employee',
    e.Salary FROM Employee e
JOIN Department d ON e.DepartmentId = d.Id
WHERE (e.DepartmentId , e.salary) IN
    (SELECT DepartmentId, MAX(Salary) FROM Employee GROUP BY DepartmentId);
```

或者这样重新排版一下：

```sql
select d.name as Department, e.name as Employee, e.salary as Salary from
Employee e join Department d on e.departmentId = d.id
where (e.departmentId, e.salary) in
(select departmentId, max(salary) from Employee group by departmentId);
```

---

196.删除语法

跟select distinct结果差不多.

```sql
delete from Person where id not in (
	select a.id from (
    	select min(id) as id from Person group by email
    ) as a
);
```

---

197.积累一下`datediff`函数的使用

```sql
select id2 as id from (
    select w1.id as id1 , w2.id as id2 from Weather w1, Weather w2 
    where datediff(w2.recordDate, w1.recordDate) = 1 and w2.temperature > w1.temperature 
) w; 
```

---

511.Game Analysis

```sql
select player_id, min(event_date) as first_login from Activity
group by player_id;
```

---

550.Game Analysis IV

```sql
select round(count(temp.player_id) / count(distinct a.player_id), 2) as fraction from Activity a
left join (
    select player_id, min(event_date) as earliestDate
    from Activity group by player_id
) as temp
on a.player_id = temp.player_id and datediff(a.event_date, temp.earliestDate) = 1;
```

好麻烦的一条指令.

---

570.`inner join`的使用

> Table: `Employee`
>
> ```
> +-------------+---------+
> | Column Name | Type    |
> +-------------+---------+
> | id          | int     |
> | name        | varchar |
> | department  | varchar |
> | managerId   | int     |
> +-------------+---------+
> id is the primary key (column with unique values) for this table.
> Each row of this table indicates the name of an employee, their department, and the id of their manager.
> If managerId is null, then the employee does not have a manager.
> No employee will be the manager of themself.
> ```
>
> Write a solution to find managers with at least **five direct reports**.
>
> Return the result table in **any order**.
>
> The result format is in the following example.
>
> **Example 1:**
>
> ```
> Input: 
> Employee table:
> +-----+-------+------------+-----------+
> | id  | name  | department | managerId |
> +-----+-------+------------+-----------+
> | 101 | John  | A          | null      |
> | 102 | Dan   | A          | 101       |
> | 103 | James | A          | 101       |
> | 104 | Amy   | A          | 101       |
> | 105 | Anne  | A          | 101       |
> | 106 | Ron   | B          | 101       |
> +-----+-------+------------+-----------+
> Output: 
> +------+
> | name |
> +------+
> | John |
> +------+
> ```

法1：

```sql
with cnt as(
    select managerId as id , count(*) as cnt from Employee group by managerId having count(*) >= 5
)
select Employee.name from Employee inner join cnt on cnt.id = Employee.id;
```

法2：

```sql
select name from Employee where id in (
	select managerId from Employee
    group by managerId having count(*) >= 5
)
```

---

577.Employee Bonus

有null，仍然考虑left join：

```sql
select e.name, b.bonus from Employee e
left join Bonus b on e.empId = b.empId where (b.bonus is NULL or b.bonus < 1000); 
```

---

585.

> Table: `Insurance`
>
> ```
> +-------------+-------+
> | Column Name | Type  |
> +-------------+-------+
> | pid         | int   |
> | tiv_2015    | float |
> | tiv_2016    | float |
> | lat         | float |
> | lon         | float |
> +-------------+-------+
> pid is the primary key (column with unique values) for this table.
> Each row of this table contains information about one policy where:
> pid is the policyholder's policy ID.
> tiv_2015 is the total investment value in 2015 and tiv_2016 is the total investment value in 2016.
> lat is the latitude of the policy holder's city. It's guaranteed that lat is not NULL.
> lon is the longitude of the policy holder's city. It's guaranteed that lon is not NULL.
> ```
>
> Write a solution to report the sum of all total investment values in 2016 `tiv_2016`, for all policyholders who:
>
> - have the same `tiv_2015` value as one or more other policyholders, and
> - are not located in the same city as any other policyholder (i.e., the (`lat, lon`) attribute pairs must be unique).
>
> Round `tiv_2016` to **two decimal places**.
>
> The result format is in the following example. 
>
> **Example 1:**
>
> ```
> Input: 
> Insurance table:
> +-----+----------+----------+-----+-----+
> | pid | tiv_2015 | tiv_2016 | lat | lon |
> +-----+----------+----------+-----+-----+
> | 1   | 10       | 5        | 10  | 10  |
> | 2   | 20       | 20       | 20  | 20  |
> | 3   | 10       | 30       | 20  | 20  |
> | 4   | 10       | 40       | 40  | 40  |
> +-----+----------+----------+-----+-----+
> Output: 
> +----------+
> | tiv_2016 |
> +----------+
> | 45.00    |
> +----------+
> Explanation: 
> The first record in the table, like the last record, meets both of the two criteria.
> The tiv_2015 value 10 is the same as the third and fourth records, and its location is unique.
> 
> The second record does not meet any of the two criteria. Its tiv_2015 is not like any other policyholders and its location is the same as the third record, which makes the third record fail, too.
> So, the result is the sum of tiv_2016 of the first and last record, which is 45.考虑先建一个新表做辅助，然后再进行判断：
> ```

```sql
with t as (
    select *, 
        count(*) over (partition by tiv_2015) as same_tiv_2015_num,
        count(*) over (partition by lat, lon) as same_position_num
    from Insurance
)

select round(sum(tiv_2016), 2) as tiv_2016 from t
where same_tiv_2015_num > 1 and same_position_num = 1; 
```

---

602.`union all`语句的使用

`union all`不会去重，而是保留所有记录，相当于拼接列

```sql
select id, count(*) as num from 
    (select requester_id as id from RequestAccepted
    union all 
    select accepter_id from RequestAccepted) h1
group by id order by num desc limit 1;
```

---

607.

```sql
with h1 as (select o.sales_id from Orders o left join company c on o.com_id = c.com_id where c.name = 'RED')
select name from SalesPerson where sales_id not in (
    select sales_id from h1
);
```

with语句的使用，先筛出跟red有关的id，再用not in除掉.

---

608.树节点

> Table: `Tree`
>
> ```
> +-------------+------+
> | Column Name | Type |
> +-------------+------+
> | id          | int  |
> | p_id        | int  |
> +-------------+------+
> id is the column with unique values for this table.
> Each row of this table contains information about the id of a node and the id of its parent node in a tree.
> The given structure is always a valid tree.
> ```
>
> Each node in the tree can be one of three types:
>
> - **"Leaf"**: if the node is a leaf node.
> - **"Root"**: if the node is the root of the tree.
> - **"Inner"**: If the node is neither a leaf node nor a root node.
>
> Write a solution to report the type of each node in the tree.
>
> Return the result table in **any order**.
>
> The result format is in the following example.
>
> ```
> Input: 
> Tree table:
> +----+------+
> | id | p_id |
> +----+------+
> | 1  | null |
> | 2  | 1    |
> | 3  | 1    |
> | 4  | 2    |
> | 5  | 2    |
> +----+------+
> Output: 
> +----+-------+
> | id | type  |
> +----+-------+
> | 1  | Root  |
> | 2  | Inner |
> | 3  | Leaf  |
> | 4  | Leaf  |
> | 5  | Leaf  |
> +----+-------+
> ```
>
> ```
> Input: 
> Tree table:
> +----+------+
> | id | p_id |
> +----+------+
> | 1  | null |
> +----+------+
> Output: 
> +----+-------+
> | id | type  |
> +----+-------+
> | 1  | Root  |
> +----+-------+
> ```

```sql
with r as (select id, 'Root' as type from Tree where p_id is null),
     l as (select id, 'Leaf' as type from Tree where id not in 
        (select distinct p_id from Tree where p_id is not null)
          and p_id is not null
        ),
     i as (select id, 'Inner' as type from Tree where id not in (select id from r) and id not in (select id from l))
select * from r union (select * from i) union (select * from l);
```

语法点要注意，多个`with`需要逗号分隔共用一个`with`.

---

610.添加列判断是否为三角形

> Table: `Triangle`
>
> ```
> +-------------+------+
> | Column Name | Type |
> +-------------+------+
> | x           | int  |
> | y           | int  |
> | z           | int  |
> +-------------+------+
> In SQL, (x, y, z) is the primary key column for this table.
> Each row of this table contains the lengths of three line segments.
> ```
>
> Report for every three line segments whether they can form a triangle.
>
> Return the result table in **any order**.
>
> The result format is in the following example.
>
> **Example 1:**
>
> ```
> Input: 
> Triangle table:
> +----+----+----+
> | x  | y  | z  |
> +----+----+----+
> | 13 | 15 | 30 |
> | 10 | 20 | 15 |
> +----+----+----+
> Output: 
> +----+----+----+----------+
> | x  | y  | z  | triangle |
> +----+----+----+----------+
> | 13 | 15 | 30 | No       |
> | 10 | 20 | 15 | Yes      |
> +----+----+----+----------+
> ```

```sql
with y as (select x, y, z, 'Yes' as triangle from Triangle
    where x + y > z and x + z > y and y + z > x),
    n as (select x, y, z, 'No' as triangle from Triangle where (x,y,z,'Yes') not in 
        (select * from y)
    )
select * from y union (select * from n);
```

---

619.biggest Single Number:取出仅出现一次的num中最大的数

```sql
select max(num) as num from(
    select num from MyNumbers group by num
    having count(num) = 1
) h;
```

---

626.位置交换

将相邻的奇数与偶数位置互换，如1和2换，3和4换；最后一个不换.

```sql
select (
    case 
        when id % 2 = 0 then id - 1
        when id % 2 = 1 and id < (select max(id) from Seat) then id + 1
        else id
    end
) id, student from Seat order by id asc;
```

asc最后可以不写，默认是asc.

---

627.`update`语句复习

```sql
update Salary set sex = (
    case sex
        when 'm' then 'f'
        else 'm'
    end
);
```

还可以三目运算符：

```sql
update Salary set sex = IF(sex='f','m','f')
```

---

1045.购买了所有商品（关系除法）

理论上最严谨：

```sql
SELECT DISTINCT customer_id
FROM Customer c1
WHERE NOT EXISTS (
    SELECT product_key
    FROM Product p
    WHERE NOT EXISTS (
        SELECT *
        FROM Customer c2
        WHERE c2.customer_id = c1.customer_id
          AND c2.product_key = p.product_key
    )
);
```

意思是：

```text
找出这样的 customer_id：
  不存在 任何一个 product，
    使得 该顾客 没有购买过这个 product
```

但是实际操作中是会超时的.

简便的方法：

```sql
select customer_id from Customer group by customer_id 
having count(distinct product_key) = (
	select count(product_key) from Product
);
```

---

1050.group by 语句的使用

一个小错误要纠正

> Table: `ActorDirector`
>
> ```
> +-------------+---------+
> | Column Name | Type    |
> +-------------+---------+
> | actor_id    | int     |
> | director_id | int     |
> | timestamp   | int     |
> +-------------+---------+
> timestamp is the primary key (column with unique values) for this table.
> ```
>
>  Write a solution to find all the pairs `(actor_id, director_id)` where the actor has cooperated with the director at least three times. Return the result table in any order. The result format is in the following example.  Example 1:
>
> ```
> Input: 
> ActorDirector table:
> +-------------+-------------+-------------+
> | actor_id    | director_id | timestamp   |
> +-------------+-------------+-------------+
> | 1           | 1           | 0           |
> | 1           | 1           | 1           |
> | 1           | 1           | 2           |
> | 1           | 2           | 3           |
> | 1           | 2           | 4           |
> | 2           | 1           | 5           |
> | 2           | 1           | 6           |
> +-------------+-------------+-------------+
> Output: 
> +-------------+-------------+
> | actor_id    | director_id |
> +-------------+-------------+
> | 1           | 1           |
> +-------------+-------------+
> Explanation: The only pair is (1, 1) where they cooperated exactly 3 times.
> ```

一开始提交了如下的东西：

```mysql
select actor_id, director_id from ActorDirector 
group by (actor_id, director_id) having count(*) >= 3;
```

只需要把括号删掉就行：

```sql
select actor_id, director_id from ActorDirector 
group by actor_id, director_id having count(*) >= 3;
```

---






> 32/105
