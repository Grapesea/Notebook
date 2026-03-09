## Leetcode MySQL

176. 找出第二高的薪水，没有就返回NULL

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



178.Rank Scores

排名有三种：`RANK()`, `DENSE_RANK()`, `` 

