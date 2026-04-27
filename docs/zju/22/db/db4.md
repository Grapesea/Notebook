# Lec04 Advanced SQL

Integrity Constraints:

```sql
create table branch2(
	branch_name varchar(30) primary key,
    branch_city varchar(30),
    assets integer not null,
    check (assets >= 100)
);
```

---

Referential Integrity:

```sql
create table customer (
    customer-name   char(20), 
    customer-street varchar(30), 
    customer-city   varchar(30), 
    primary key (customer-name)
);

create table branch (
    branch-name varchar(15), 
	branch-city varchar(30), 
	assets integer, 
	primary key (branch-name)
);

create table account (
	account_number char(10),
    branch_name char(15),
    balance integer,
    primary key (account_number),
    foreign key (branch_name) references branch
);

create table depositor (
	customer_name char(20),
    account_number char(10),
    primary key (customer_name, account_number), -- 复合主键
    foreign key (account_number) references account,
    foreign key (customer_name) references customer
);
```

---

Assertions:

没有一个银行的存款多于贷款额

```sql
create assertion sum_constraint check
	(not exists
     	(select * from branch B
         where (
         	select sum(amount) from loan 
             where loan.branch_name	= B.branch_name) 
         	> 
         	(select sum(balance) from account
            where account.branch_name = B.branch_name)
        )
    )
```

---

