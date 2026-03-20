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

180.连续三天登录

```sql
select distinct l1.num as ConsecutiveNums 
from Logs l1, Logs l2, Logs l3
where l1.id = l2.id-1 and l2.id = l3.id-1 and l1.num = l2.num and l2.num = l3.num;
```

181.easy

```sql
select e1.name as Employee from Employee e1, Employee e2 where e1.managerId = e2.id and e1.salary > e2.salary
```

182.easy

```sql
select email as Email from Person group by email
having COUNT(email) > 1
```

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



196.删除语法

跟select distinct结果差不多.

```sql
delete from Person where id not in (
	select a.id from (
    	select min(id) as id from Person group by email
    ) as a
);
```



197.积累一下`datediff`函数的使用

```sql
select id2 as id from (
    select w1.id as id1 , w2.id as id2 from Weather w1, Weather w2 
    where datediff(w2.recordDate, w1.recordDate) = 1 and w2.temperature > w1.temperature 
) w; 
```



511.Game Analysis

```sql
select player_id, min(event_date) as first_login from Activity
group by player_id;
```



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





> 15/105
