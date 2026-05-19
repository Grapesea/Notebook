> 表示完全来自CS61B: 2024Spring

## Testing

Starter Code: `Sort` (ad Hoc vec.)

```java
public class TestSort{
    public static void testSort() {
        String[] input = {"i", "have", "an", "egg"};
        String[] expected = {"an", "egg", "have", "i"};
        Sort.sort(input);
        for (int i = 0; i < input.length; i += 1) {
            if (!input[i].equals(expected[i])) {
                System.out.println("Mismatch in position " + i + ", expected: " + expected + ", but got: " + input[i] + ".");
                break;
            }
        }
    }

    public static void main(String[] args) {
        testSort();
    }
}
```

主文件：

```java
public class Sort {
    /** Sorts strings destructively. */
    public static void sort(String[] x) {        
    }
}
```

> In fact, this is a lot like the situation where you have an autograder for a class, and you find yourself hooked on the idea of getting the autograder to give you its love and approval. You now have the ability to create a judge for your code, whose esteem you can only win by completing the code correctly.

Java有一个很刁钻的点：字符串`==`表示比较地址的各bit是否相同，所以正确的比较字符串内容的方法是`.equals()`.

---

Google给了一个新的测试方法：

```java
import static com.google.common.truth.Truth.assertThat;
public class TestSort {
   /** Tests the sort method of the Sort class. */
   public static void testSort() {
       String[] input = {"cows", "dwell", "above", "clouds"};
       String[] expected = {"above", "clouds", "cows", "dwell"};
       Sort.sort(input);

       assertThat(input).isEqualTo(expected); // much simpler.
   }

   public static void main(String[] args) {
       testSort();
   }
}
```



