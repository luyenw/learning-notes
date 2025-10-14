# Java 11 OCP Notes

*"Tài liệu tổng hợp kiến thức chuẩn bị cho kỳ thi Oracle Certified Professional Java SE 11 Developer, bao gồm các chủ đề: Kiểu dữ liệu và biến, Lập trình hướng đối tượng, Cấu trúc điều khiển, Mảng và Collections, Xử lý ngoại lệ, Lập trình đa luồng (Concurrency) và các khái niệm nâng cao của Java."*

## 1. Java Data Types

### 1.1. Primitive Types

Các kiểu primitive trong Java (kích thước theo byte):

| Kiểu | Kích thước | Min Value | Max Value | Giá trị mặc định |
|------|-----------|-----------|-----------|------------------|
| `byte` | 1 byte | -128 | 127 | 0 |
| `short` | 2 bytes | -32,768 | 32,767 | 0 |
| `char` | 2 bytes | 0 | 65,535 | '\u0000' |
| `int` | 4 bytes | -2³¹ | 2³¹-1 | 0 |
| `long` | 8 bytes | -2⁶³ | 2⁶³-1 | 0L |
| `float` | 4 bytes | ~±3.4e-38 | ~±3.4e+38 | 0.0f |
| `double` | 8 bytes | ~±4.9e-324 | ~±1.7e+308 | 0.0d |
| `boolean` | JVM dependent | - | - | false |

**Lưu ý quan trọng:**
- Mặc định của số nguyên là `int`, số thực là `double`
- `char` là kiểu unsigned (0 đến 65,535) ~ unsigned short
- **Promotion**: Các toán hạng nhỏ hơn `int` tự động được promote lên `int` trước khi thực hiện tính toán

**Ví dụ về Promotion:**

```java
// ✅ Valid - Promotion tự động
byte b1 = 10;
byte b2 = 20;
int result = b1 + b2;  // b1, b2 được promote lên int

// ❌ Invalid - Không thể gán int về byte mà không ép kiểu
byte b3 = b1 + b2;  // Compile error: incompatible types

// ✅ Valid - Cần ép kiểu tường minh
byte b3 = (byte)(b1 + b2);

// ✅ Valid - Literal được compiler xử lý
byte b4 = 10 + 20;  // Compiler tính toán = 30, fit trong byte
```

**Ví dụ về Literals:**

```java
// ✅ Valid - Integer literals
int decimal = 100;
int hex = 0x64;        // 100 in hex
int binary = 0b1100100; // 100 in binary
int withUnderscore = 1_000_000; // Dễ đọc hơn

// ✅ Valid - Long literals (cần suffix L hoặc l)
long longValue = 100L;
long bigValue = 9_223_372_036_854_775_807L;

// ✅ Valid - Float literals (cần suffix F hoặc f)
float floatValue = 3.14F;
float scientific = 1.23e-4f;

// ✅ Valid - Double literals
double doubleValue = 3.14;
double doubleValue2 = 3.14D; // D là optional

// ❌ Invalid - Missing suffix
float wrong = 3.14;  // Compile error: incompatible types (double -> float)
```

---

### 1.2. Widening & Narrowing Casting

**Widening Casting (Implicit - Tự động):**
Khi gán biến có kiểu nhỏ hơn cho biến kiểu lớn hơn, không cần ép kiểu tường minh.

**Thứ tự widening:** `byte` → `short` → `int` → `long` → `float` → `double`
                      `char` → `int` → `long` → `float` → `double`

```java
// ✅ Valid - Widening tự động
byte b = 10;
short s = b;      // byte -> short
int i = s;        // short -> int
long l = i;       // int -> long
float f = l;      // long -> float
double d = f;     // float -> double

// ✅ Valid - char widening
char c = 'A';     // 65
int charToInt = c; // = 65

// ✅ Valid - Widening trong biểu thức
int x = 10;
double result = x / 4;  // int / int = 2, sau đó 2 -> 2.0 (widening)
double result2 = x / 4.0;  // int / double = 2.5 (x được widen lên double)
```

**Narrowing Casting (Explicit - Tường minh):**
Khi gán biến có kiểu lớn hơn cho biến có kiểu nhỏ hơn, **bắt buộc** phải ép kiểu tường minh.

```java
// ✅ Valid - Narrowing với ép kiểu
double d = 9.99;
int i = (int) d;        // = 9 (mất phần thập phân)
byte b = (byte) i;      // = 9

// ❌ Invalid - Thiếu ép kiểu
int x = 100;
byte b = x;  // Compile error: incompatible types

// ✅ Valid - Narrowing có thể mất dữ liệu
int big = 130;
byte small = (byte) big;  // = -126 (overflow!)

// ✅ Valid - Narrowing với literal (compiler check)
byte literal = 100;  // OK, 100 fits in byte
// ❌ Invalid
byte tooBig = 200;   // Compile error: incompatible types

// ✅ Valid - char narrowing
int num = 65;
char ch = (char) num;  // = 'A'
```

---

### 1.3. Wrapper Classes

Mỗi kiểu primitive đều có wrapper class tương ứng:

| Primitive | Wrapper Class |
|-----------|---------------|
| `byte` | `Byte` |
| `short` | `Short` |
| `char` | `Character` |
| `int` | `Integer` |
| `long` | `Long` |
| `float` | `Float` |
| `double` | `Double` |
| `boolean` | `Boolean` |

**So sánh Wrapper:**

```java
Integer a = 100;
Integer b = 100;
Integer c = new Integer(100);
Integer d = 200;
Integer e = 200;

// ✅ == so sánh reference
System.out.println(a == b);        // true (cùng object trong cache)
System.out.println(a == c);        // false (c là object mới)
System.out.println(d == e);        // false (ngoài cache range)

// ✅ Objects.equals() so sánh giá trị
System.out.println(Objects.equals(a, b));  // true
System.out.println(Objects.equals(a, c));  // true
System.out.println(Objects.equals(d, e));  // true

// ✅ equals() method
System.out.println(a.equals(b));   // true
System.out.println(a.equals(c));   // true
System.out.println(a.equals(d));   // false (khác giá trị)
```

**Wrapper Caching:**

Wrapper classes có cơ chế cache giống như String pool:

**Integer, Long, Short, Byte:** Cache từ **-128 đến 127**

```java
// ✅ Trong cache range [-128, 127]
Integer i1 = 127;
Integer i2 = 127;
System.out.println(i1 == i2);  // true (cùng object)

Integer i3 = -128;
Integer i4 = -128;
System.out.println(i3 == i4);  // true

// ❌ Ngoài cache range
Integer i5 = 128;
Integer i6 = 128;
System.out.println(i5 == i6);  // false (khác object)

// ✅ Sử dụng new -> không dùng cache
Integer i7 = new Integer(127);
Integer i8 = new Integer(127);
System.out.println(i7 == i8);  // false
```

**Boolean:** Cache `TRUE` và `FALSE`

```java
// ✅ Boolean cache
Boolean b1 = true;
Boolean b2 = true;
System.out.println(b1 == b2);  // true

Boolean b3 = Boolean.valueOf(false);
Boolean b4 = Boolean.valueOf(false);
System.out.println(b3 == b4);  // true

// ❌ Sử dụng new
Boolean b5 = new Boolean(true);
Boolean b6 = new Boolean(true);
System.out.println(b5 == b6);  // false
```

**Autoboxing & Unboxing:**

```java
// ✅ Autoboxing - primitive -> wrapper
int primitive = 10;
Integer wrapper = primitive;  // tự động boxing

// ✅ Unboxing - wrapper -> primitive
Integer boxed = 20;
int unboxed = boxed;  // tự động unboxing

// ✅ Hoạt động trong biểu thức
Integer a = 10;
Integer b = 20;
int sum = a + b;  // unboxing -> tính toán -> 30

// ❌ NullPointerException risk
Integer nullValue = null;
int x = nullValue;  // Runtime error: NullPointerException!
```

---

### 1.4. String (Immutable, Pooling)

String là **immutable** - không thể thay đổi nội dung sau khi tạo.

**String Pool:**
- String literals được JVM quản lý trong **String Pool** (trong Heap từ Java 7+)
- 2 literals giống nhau sẽ trỏ đến cùng một object

```java
// ✅ String literals - sử dụng String pool
String s1 = "Hello";
String s2 = "Hello";
System.out.println(s1 == s2);  // true (cùng reference)

// ✅ String object - tạo object mới
String s3 = new String("Hello");
System.out.println(s1 == s3);  // false (khác reference)
System.out.println(s1.equals(s3));  // true (cùng giá trị)

// ✅ intern() - đưa vào pool
String s4 = new String("Hello").intern();
System.out.println(s1 == s4);  // true

// ✅ String concatenation với literal
String s5 = "Hel" + "lo";  // Compile-time constant
System.out.println(s1 == s5);  // true

// ❌ String concatenation với variable
String part = "Hel";
String s6 = part + "lo";  // Runtime concatenation
System.out.println(s1 == s6);  // false
```

**String Immutability:**

```java
// ✅ String không thay đổi
String str = "Hello";
str.concat(" World");  // Tạo String mới, không ảnh hưởng str
System.out.println(str);  // "Hello"

// ✅ Phải gán lại để giữ kết quả
str = str.concat(" World");
System.out.println(str);  // "Hello World"

// ✅ Các method trả về String mới
String original = "Java";
String upper = original.toUpperCase();  // "JAVA"
System.out.println(original);  // "Java" (không đổi)
System.out.println(upper);     // "JAVA"
```

**Các method thường dùng:**

```java
String str = "Hello World";

// ✅ Length và charAt
str.length();           // 11
str.charAt(0);          // 'H'
str.charAt(6);          // 'W'

// ✅ Substring
str.substring(0, 5);    // "Hello"
str.substring(6);       // "World"

// ✅ indexOf
str.indexOf("o");       // 4
str.lastIndexOf("o");   // 7
str.indexOf("xyz");     // -1 (không tìm thấy)

// ✅ Replace
str.replace("World", "Java");  // "Hello Java"
str.replaceAll("[aeiou]", "");  // "Hll Wrld" (regex)

// ✅ Split
String csv = "a,b,c";
String[] parts = csv.split(",");  // ["a", "b", "c"]

// ✅ Trim và strip (Java 11+)
"  hello  ".trim();     // "hello"
"  hello  ".strip();    // "hello" (Unicode-aware)

// ✅ Case conversion
str.toLowerCase();      // "hello world"
str.toUpperCase();      // "HELLO WORLD"

// ✅ Checking
str.startsWith("Hello"); // true
str.endsWith("World");   // true
str.contains("lo Wo");   // true
str.isEmpty();           // false
str.isBlank();           // false (Java 11+)
```

---

### 1.5. StringBuilder & StringBuffer (Mutable)

Cho phép thay đổi nội dung chuỗi mà không tạo object mới.

**StringBuilder:**
- **Mutable** - có thể thay đổi nội dung
- **Không thread-safe** - nhanh hơn
- Dùng khi không cần đồng bộ

```java
// ✅ Tạo StringBuilder
StringBuilder sb1 = new StringBuilder();          // capacity = 16
StringBuilder sb2 = new StringBuilder(50);        // capacity = 50
StringBuilder sb3 = new StringBuilder("Hello");   // capacity = 16 + 5

// ✅ append - nối chuỗi
StringBuilder sb = new StringBuilder("Hello");
sb.append(" ");
sb.append("World");
sb.append('!');
sb.append(123);
System.out.println(sb);  // "Hello World!123"

// ✅ Method chaining
sb.append(" Java").append(" ").append(11);  // "Hello World!123 Java 11"

// ✅ insert - chèn
sb.insert(5, " Beautiful");  // "Hello Beautiful World!123 Java 11"

// ✅ delete và deleteCharAt
sb.delete(6, 16);      // Xóa "Beautiful "
sb.deleteCharAt(5);    // Xóa space

// ✅ reverse - đảo ngược
StringBuilder rev = new StringBuilder("abc");
rev.reverse();  // "cba"

// ✅ replace
sb.replace(0, 5, "Hi");  // Thay "Hello" bằng "Hi"

// ✅ substring - trả về String (không thay đổi StringBuilder)
String sub = sb.substring(0, 2);  // "Hi"

// ✅ toString - chuyển thành String immutable
String result = sb.toString();

// ✅ Capacity management
sb.capacity();              // Kiểm tra capacity
sb.ensureCapacity(100);     // Đảm bảo capacity >= 100
sb.trimToSize();            // Giảm capacity = length
```

**StringBuffer:**
- **Mutable** - giống StringBuilder
- **Thread-safe** - tất cả methods đều `synchronized`
- **Chậm hơn** StringBuilder do synchronized
- Dùng trong môi trường multi-threaded

```java
// ✅ StringBuffer - tương tự StringBuilder nhưng thread-safe
StringBuffer sbuf = new StringBuffer("Thread");
sbuf.append(" Safe");
sbuf.insert(0, "Is ");
System.out.println(sbuf);  // "Is Thread Safe"

// ✅ Trong multi-threaded environment
public class Counter {
    private StringBuffer buffer = new StringBuffer();

    public void append(String text) {
        buffer.append(text);  // Thread-safe
    }
}
```

**So sánh String vs StringBuilder vs StringBuffer:**

```java
// ❌ Không hiệu quả - tạo nhiều String objects
String result = "";
for (int i = 0; i < 1000; i++) {
    result += i;  // Tạo 1000 String objects!
}

// ✅ Hiệu quả - StringBuilder
StringBuilder sb = new StringBuilder();
for (int i = 0; i < 1000; i++) {
    sb.append(i);  // Chỉ 1 object, modify in-place
}
String result = sb.toString();

// ✅ Thread-safe khi cần
StringBuffer sbuf = new StringBuffer();
// ... use in multi-threaded context
```

---

### 1.6. var Keyword (Java 10+)

`var` cho phép compiler tự suy luận kiểu dữ liệu (Local Variable Type Inference).

**Sử dụng hợp lệ:**

```java
// ✅ Local variable với initialization
var number = 10;              // int
var text = "Hello";           // String
var list = new ArrayList<>(); // ArrayList<Object>
var map = Map.of("key", "value");  // Map<String, String>

// ✅ Trong loop
var numbers = List.of(1, 2, 3);
for (var num : numbers) {     // Integer
    System.out.println(num);
}

for (var i = 0; i < 10; i++) {  // int
    // ...
}

// ✅ Với method return type
var result = getString();     // String (từ return type)
var length = result.length(); // int
```

**Không thể sử dụng:**

```java
// ❌ Không có initialization
var x;  // Compile error: cannot infer type

// ❌ Initialize với null
var y = null;  // Compile error: cannot infer type

// ❌ Instance variable
class MyClass {
    var field = 10;  // Compile error
}

// ❌ Static variable
static var count = 0;  // Compile error

// ❌ Method parameter
void method(var param) {  // Compile error
}

// ❌ Method return type
var getValue() {  // Compile error
    return 10;
}

// ❌ Constructor parameter
MyClass(var value) {  // Compile error
}

// ✅ Lambda parameter (Java 11+)
Function<String, Integer> f = (var s) -> s.length();  // OK trong Java 11+
```

**Lưu ý với var:**

```java
// ✅ var không phải keyword, có thể dùng làm tên biến
int var = 10;  // Hợp lệ nhưng không khuyến khích

// ✅ Kiểu được infer tại compile-time
var text = "Hello";
text = 123;  // Compile error: incompatible types (vẫn là String)

// ✅ Với diamond operator
var list = new ArrayList<String>();  // ArrayList<String>
var map = new HashMap<>();           // HashMap<Object, Object>

// ❌ Khó đọc
var result = process();  // Kiểu gì? Phải xem method

// ✅ Rõ ràng
var name = getName();    // Rõ là String từ tên method
```

---

### 1.7. Độ ưu tiên toán tử (Operator Precedence)

Thứ tự ưu tiên từ cao đến thấp:

| Độ ưu tiên | Toán tử | Mô tả | Associativity |
|-----------|---------|-------|---------------|
| 1 | `()` `[]` `.` | Parentheses, Array, Member access | Left-to-right |
| 2 | `++` `--` | Postfix increment/decrement | Left-to-right |
| 3 | `++` `--` `+` `-` `!` `~` | Prefix, Unary | Right-to-left |
| 4 | `(type)` | Type cast | Right-to-left |
| 5 | `*` `/` `%` | Multiplicative | Left-to-right |
| 6 | `+` `-` | Additive | Left-to-right |
| 7 | `<<` `>>` `>>>` | Shift | Left-to-right |
| 8 | `<` `<=` `>` `>=` `instanceof` | Relational | Left-to-right |
| 9 | `==` `!=` | Equality | Left-to-right |
| 10 | `&` | Bitwise AND | Left-to-right |
| 11 | `^` | Bitwise XOR | Left-to-right |
| 12 | `\|` | Bitwise OR | Left-to-right |
| 13 | `&&` | Logical AND | Left-to-right |
| 14 | `\|\|` | Logical OR | Left-to-right |
| 15 | `? :` | Ternary | Right-to-left |
| 16 | `=` `+=` `-=` `*=` `/=` `%=` etc. | Assignment | **Right-to-left** |

**Ví dụ về precedence:**

```java
// ✅ Multiplicative > Additive
int result = 2 + 3 * 4;  // = 2 + 12 = 14, không phải 20

// ✅ Sử dụng parentheses
int result2 = (2 + 3) * 4;  // = 5 * 4 = 20

// ✅ Unary > Multiplicative
int x = 5;
int y = -x * 2;  // = -5 * 2 = -10

// ✅ Relational > Equality
boolean b = 5 > 3 == true;  // (5 > 3) == true = true == true = true

// ✅ Logical AND > Logical OR
boolean result = true || false && false;  // true || (false && false) = true

// ✅ Assignment là right-associative
int a, b, c;
a = b = c = 10;  // c = 10, sau đó b = c, sau đó a = b

// ✅ Ternary cũng right-associative
int value = true ? 1 : false ? 2 : 3;
// = true ? 1 : (false ? 2 : 3) = 1

// ✅ Increment/Decrement
int i = 5;
int j = ++i * 2;  // (++i) * 2 = 6 * 2 = 12, i = 6
int k = i++ * 2;  // (i++) * 2 = 6 * 2 = 12, sau đó i = 7
```

**Lưu ý quan trọng:**

**Phép gán có độ ưu tiên THẤP NHẤT:**

```java
int a = 5;
int b = 10;
int c = a < b ? a : b;  // OK: (a < b) ? a : b, sau đó gán cho c
```

**Short-circuit Evaluation:**

Phép `&&` và `||` là short-circuit, tức là có thể không evaluate toán hạng thứ hai nếu kết quả đã chắc chắn.

```java
// ✅ Short-circuit - không evaluate phần thứ 2
boolean result = false && (1/0 > 0);  // false, không evaluate (1/0)
boolean result2 = true || (1/0 > 0);  // true, không evaluate (1/0)

// ❌ Non-short-circuit - luôn evaluate cả 2 toán hạng
boolean result3 = false & (1/0 > 0);  // ArithmeticException!
boolean result4 = true | (1/0 > 0);   // ArithmeticException!
```
### 1.8. Casting Reference Types

**Upcasting (Implicit - Tự động):**
- Chuyển từ subclass → superclass
- Tự động, không cần ép kiểu
- Luôn an toàn (mọi Dog đều là Animal)

```java
// ✅ Upcasting - tự động
class Animal { }
class Dog extends Animal { }

Dog dog = new Dog();
Animal animal = dog;  // Upcasting: Dog -> Animal (tự động)
Object obj = dog;     // Dog -> Object (tự động)
```

**Downcasting (Explicit - Tường minh):**
- Chuyển từ superclass → subclass
- Phải ép kiểu tường minh: `(SubType) object`
- Có thể gây `ClassCastException` nếu sai kiểu runtime
- Nên dùng `instanceof` để kiểm tra trước

```java
// ✅ Valid - Downcasting với instanceof check
Animal animal = new Dog();
if (animal instanceof Dog) {
    Dog dog = (Dog) animal;  // An toàn
    dog.bark();
}

// ❌ ClassCastException - Sai kiểu runtime
Animal animal2 = new Cat();
Dog dog2 = (Dog) animal2;  // Runtime error: ClassCastException!

// ✅ Sử dụng instanceof để tránh lỗi
if (animal2 instanceof Dog) {
    Dog dog3 = (Dog) animal2;  // Không chạy vào đây
}
```

---

## 2. OOP Approach

### 2.1. Access Modifiers

**Tóm tắt:**
- `private`: Chỉ trong class
- `default` (không có modifier): Trong cùng package
- `protected`: Trong package HOẶC subclass (có hạn chế)
- `public`: Mọi nơi

**Lưu ý đặc biệt:** `protected` trong subclass (khác package) chỉ truy cập được qua `this` hoặc object kiểu subclass, KHÔNG qua reference kiểu superclass.

| Modifier | Cùng Class | Cùng Package | Subclass (khác package) | Khác Package |
|----------|-----------|--------------|------------------------|--------------|
| `private` | ✅ | ❌ | ❌ | ❌ |
| `default` (no modifier) | ✅ | ✅ | ❌ | ❌ |
| `protected` | ✅ | ✅ | ✅ | ❌ |
| `public` | ✅ | ✅ | ✅ | ✅ |

**Ví dụ chi tiết:**

```java
// File: com/example/base/Parent.java
package com.example.base;

public class Parent {
    public int publicField = 1;
    protected int protectedField = 2;
    int defaultField = 3;           // default/package-private
    private int privateField = 4;

    public void publicMethod() { }
    protected void protectedMethod() { }
    void defaultMethod() { }
    private void privateMethod() { }
}

// ✅ Cùng package - truy cập được public, protected, default
package com.example.base;

public class SamePackage {
    void test() {
        Parent p = new Parent();
        p.publicField = 10;      // ✅ OK
        p.protectedField = 20;   // ✅ OK
        p.defaultField = 30;     // ✅ OK
        p.privateField = 40;     // ❌ Compile error
    }
}

// File: com/example/other/Child.java
package com.example.other;
import com.example.base.Parent;

public class Child extends Parent {
    void test() {
        // ✅ Truy cập qua this (inheritance)
        this.publicField = 10;      // ✅ OK
        this.protectedField = 20;   // ✅ OK
        this.defaultField = 30;     // ❌ Compile error (khác package)
        this.privateField = 40;     // ❌ Compile error

        // ✅ Truy cập qua Child object
        Child child = new Child();
        child.protectedField = 50;  // ✅ OK

        // ❌ KHÔNG thể truy cập protected qua Parent reference!
        Parent parent = new Child();
        parent.protectedField = 60;  // ❌ Compile error!

        // ✅ Chỉ public mới truy cập được qua Parent reference
        parent.publicField = 70;     // ✅ OK
    }
}

// File: com/example/other/OtherClass.java
package com.example.other;
import com.example.base.Parent;

public class OtherClass {
    void test() {
        Parent p = new Parent();
        p.publicField = 10;      // ✅ OK (public)
        p.protectedField = 20;   // ❌ Compile error (không phải subclass)
        p.defaultField = 30;     // ❌ Compile error (khác package)
        p.privateField = 40;     // ❌ Compile error
    }
}
```

**Quy tắc đặc biệt với `protected`:**

```java
// ✅ Protected trong subclass
package com.example.other;
import com.example.base.Parent;

public class Child extends Parent {
    void accessProtected() {
        // ✅ Qua this
        this.protectedMethod();

        // ✅ Qua Child object
        Child c = new Child();
        c.protectedMethod();

        // ❌ KHÔNG qua Parent reference
        Parent p = new Parent();
        p.protectedMethod();  // ❌ Compile error!

        // ❌ KHÔNG qua Parent reference dù runtime là Child
        Parent p2 = new Child();
        p2.protectedMethod();  // ❌ Compile error!
    }
}
```

---

### 2.2. Inheritance (Kế thừa)

**Tóm tắt:**
- Subclass kế thừa **tất cả** members từ superclass (kể cả `private`, nhưng không truy cập được)
- Chỉ truy cập được members không phải `private`
- Constructor KHÔNG được kế thừa
- Mọi constructor của subclass đều phải gọi superclass constructor (tường minh hoặc ngầm định)

**Constructor Chaining:**
- Constructor của subclass tự động gọi `super()` nếu không có `super(args)` hoặc `this(args)`
- Nếu superclass không có no-args constructor → subclass PHẢI gọi `super(args)` tường minh
- `super()` hoặc `this()` phải là câu lệnh đầu tiên trong constructor

```java
class Animal {
    String name;

    // No-args constructor
    public Animal() {
        System.out.println("Animal() called");
    }

    public Animal(String name) {
        this.name = name;
        System.out.println("Animal(String) called: " + name);
    }
}

class Dog extends Animal {
    String breed;

    // ✅ Tự động gọi super() nếu không có super()/this()
    public Dog() {
        // super(); // Compiler tự thêm
        System.out.println("Dog() called");
    }

    // ✅ Gọi super constructor tường minh
    public Dog(String name, String breed) {
        super(name);  // Phải là câu lệnh đầu tiên
        this.breed = breed;
        System.out.println("Dog(String, String) called");
    }
}

// Test
Dog d1 = new Dog();
// Output:
// Animal() called
// Dog() called

Dog d2 = new Dog("Max", "Labrador");
// Output:
// Animal(String) called: Max
// Dog(String, String) called
```

**Lỗi thường gặp:**

```java
class Parent {
    // ❌ Không có no-args constructor
    public Parent(String name) {
        System.out.println("Parent: " + name);
    }
}

class Child extends Parent {
    // ❌ Compile error: constructor Parent() is undefined
    public Child() {
        // Compiler cố gọi super() nhưng không tồn tại
    }

    // ✅ Phải gọi super(String) tường minh
    public Child(String name) {
        super(name);
    }
}
```

**Thứ tự khởi tạo (Initialization Order):**

```java
class Parent {
    static int staticParent = initStaticParent();
    int fieldParent = initFieldParent();

    static {
        System.out.println("2. Parent static block");
    }

    {
        System.out.println("6. Parent instance block");
    }

    public Parent() {
        System.out.println("7. Parent constructor");
    }

    static int initStaticParent() {
        System.out.println("1. Parent static field");
        return 1;
    }

    int initFieldParent() {
        System.out.println("5. Parent instance field");
        return 1;
    }
}

class Child extends Parent {
    static int staticChild = initStaticChild();
    int fieldChild = initFieldChild();

    static {
        System.out.println("4. Child static block");
    }

    {
        System.out.println("9. Child instance block");
    }

    public Child() {
        System.out.println("10. Child constructor");
    }

    static int initStaticChild() {
        System.out.println("3. Child static field");
        return 2;
    }

    int initFieldChild() {
        System.out.println("8. Child instance field");
        return 2;
    }
}

// Test
Child c = new Child();
```

**Output:**
```
1. Parent static field
2. Parent static block
3. Child static field
4. Child static block
5. Parent instance field
6. Parent instance block
7. Parent constructor
8. Child instance field
9. Child instance block
10. Child constructor
```

**Thứ tự khởi tạo:**
1. **Static members của Parent** (fields → blocks) - chỉ 1 lần
2. **Static members của Child** (fields → blocks) - chỉ 1 lần
3. **Instance fields và blocks của Parent**
4. **Constructor của Parent**
5. **Instance fields và blocks của Child**
6. **Constructor của Child**

---

### 2.3. Polymorphism (Đa hình)

**Tóm tắt:**
- **Compile-time type** (bên trái): Quyết định methods/fields nào có thể GỌI
- **Runtime type** (bên phải): Quyết định method nào được THỰC THI
- Instance methods: Dựa vào runtime type (polymorphism)
- Static methods: Dựa vào compile-time type (method hiding, KHÔNG phải polymorphism)
- Fields: Luôn dựa vào compile-time type (field hiding, KHÔNG phải polymorphism)

**Compile-time Type vs Runtime Type:**

```java
class Animal {
    public void makeSound() {
        System.out.println("Animal sound");
    }

    public void eat() {
        System.out.println("Animal eating");
    }
}

class Dog extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Bark!");
    }

    public void fetch() {
        System.out.println("Fetching...");
    }
}

// ✅ Polymorphism
Animal animal = new Dog();  // Compile-type: Animal, Runtime-type: Dog

// ✅ Method được gọi dựa trên RUNTIME type
animal.makeSound();  // "Bark!" (Dog's method)
animal.eat();        // "Animal eating" (inherited)

// ❌ Compile error - method không tồn tại trong compile-type
animal.fetch();  // Compile error: cannot find symbol

// ✅ Cần downcast để gọi
if (animal instanceof Dog) {
    ((Dog) animal).fetch();  // "Fetching..."
}
```

**Method Overriding:**

**Quy tắc overriding:**
- Cùng signature (tên + parameters)
- Return type: Cùng kiểu HOẶC subtype (covariant return)
- Access modifier: Bằng hoặc rộng hơn (không được hẹp hơn)
- Exceptions: Cùng hoặc hẹp hơn (đối với checked exceptions)
- `final` methods không thể override
- `static` methods không thể override (chỉ hide)

```java
class Parent {
    public String getName() {
        return "Parent";
    }

    // ✅ Overriding rules
    public Number getValue() {
        return 100;
    }
}

class Child extends Parent {
    // ✅ Valid overriding
    @Override
    public String getName() {  // Cùng signature
        return "Child";
    }

    // ✅ Covariant return type
    @Override
    public Integer getValue() {  // Integer là subclass của Number
        return 200;
    }

    // ❌ Invalid overriding examples:

    // Compile error: weaker access privileges
    // @Override
    // private String getName() { return ""; }

    // Compile error: incompatible return type
    // @Override
    // public String getValue() { return ""; }
}
```

**Method Hiding (Static Methods):**

**Điểm khác biệt quan trọng:**
- Static methods KHÔNG bị override, chỉ bị **hide**
- Method được gọi dựa vào **compile-time type** (KHÔNG phải runtime type)
- Đây KHÔNG phải polymorphism

```java
class Parent {
    public static void staticMethod() {
        System.out.println("Parent static");
    }

    public void instanceMethod() {
        System.out.println("Parent instance");
    }
}

class Child extends Parent {
    // Method hiding - không phải overriding!
    public static void staticMethod() {
        System.out.println("Child static");
    }

    // Method overriding
    @Override
    public void instanceMethod() {
        System.out.println("Child instance");
    }
}

// Test
Parent p1 = new Parent();
Parent p2 = new Child();  // Runtime type: Child
Child c = new Child();

// ✅ Static method - dựa vào COMPILE-TIME type
p1.staticMethod();  // "Parent static"
p2.staticMethod();  // "Parent static" (không phải "Child static"!)
c.staticMethod();   // "Child static"

// ✅ Instance method - dựa vào RUNTIME type
p1.instanceMethod();  // "Parent instance"
p2.instanceMethod();  // "Child instance" (polymorphism!)
c.instanceMethod();   // "Child instance"
```

**Field Hiding:**

**Lưu ý:**
- Fields KHÔNG BAO GIỜ bị override, chỉ bị **hide**
- Giá trị field được truy cập dựa vào **compile-time type**

```java
class Parent {
    public String name = "Parent";
}

class Child extends Parent {
    public String name = "Child";  // Hiding, không phải overriding
}

// Test
Parent p = new Child();
Child c = new Child();

System.out.println(p.name);  // "Parent" (compile-time type)
System.out.println(c.name);  // "Child"
System.out.println(((Child) p).name);  // "Child" (downcast)
```

**Covariant Return Types:**

**Quy tắc:**
- Overriding method có thể return subtype của type trong overridden method
- Giúp tránh casting khi gọi method trên subclass reference

```java
class Animal {
    public Animal reproduce() {
        return new Animal();
    }
}

class Dog extends Animal {
    // ✅ Covariant return - Dog là subclass của Animal
    @Override
    public Dog reproduce() {
        return new Dog();
    }
}

class Cat extends Animal {
    // ✅ Có thể return chính xác kiểu Cat
    @Override
    public Cat reproduce() {
        return new Cat();
    }
}

// Test
Animal animal = new Dog();
Animal baby = animal.reproduce();  // Runtime type: Dog

Dog dog = new Dog();
Dog puppy = dog.reproduce();  // Không cần cast!
```

---

### 2.4. Abstraction (Abstract Class & Interface)

**Abstract Class - Tóm tắt:**
- Dùng từ khóa `abstract`
- Có thể có: abstract methods + concrete methods + constructor + instance fields
- KHÔNG thể tạo instance trực tiếp
- Subclass phải implement tất cả abstract methods (trừ khi subclass cũng abstract)
- Dùng khi: Có shared state/implementation giữa các subclasses

**Abstract Class:**

```java
// ✅ Abstract class
public abstract class Animal {
    // ✅ Có instance fields
    private String name;

    // ✅ Có constructor
    public Animal(String name) {
        this.name = name;
    }

    // ✅ Abstract method - không có body
    public abstract void makeSound();

    // ✅ Concrete method - có body
    public void eat() {
        System.out.println(name + " is eating");
    }

    // ✅ Static method
    public static void info() {
        System.out.println("Animal class");
    }
}

// ✅ Concrete subclass phải implement tất cả abstract methods
class Dog extends Animal {
    public Dog(String name) {
        super(name);
    }

    @Override
    public void makeSound() {
        System.out.println("Bark!");
    }
}

// ✅ Abstract subclass không cần implement
abstract class Bird extends Animal {
    public Bird(String name) {
        super(name);
    }
    // Không implement makeSound() - vẫn OK vì Bird là abstract
}

// ❌ Cannot instantiate abstract class
// Animal a = new Animal("Test");  // Compile error!

// ✅ Có thể tạo instance của concrete subclass
Animal dog = new Dog("Max");
dog.makeSound();  // "Bark!"
dog.eat();        // "Max is eating"
```

**Interface - Tóm tắt:**
- Từ khóa `interface`
- Có thể có:
  - **Abstract methods** (mặc định `public abstract`)
  - **Default methods** - có body (Java 8+)
  - **Static methods** - có body (Java 8+)
  - **Private methods** - có body, code reuse (Java 9+)
  - **Constants** - mặc định `public static final`
- KHÔNG có: constructor, instance fields
- Implement nhiều interfaces (multiple inheritance)
- Static methods KHÔNG được kế thừa trong implementing class
- Dùng khi: Định nghĩa contract/capability

**Interface:**

```java
// ✅ Interface trong Java 11
public interface Flyable {
    // ✅ Constant - mặc định public static final
    int MAX_ALTITUDE = 10000;
    // Tương đương: public static final int MAX_ALTITUDE = 10000;

    // ✅ Abstract method - mặc định public abstract
    void fly();
    // Tương đương: public abstract void fly();

    // ✅ Default method - có body (Java 8+)
    default void land() {
        System.out.println("Landing...");
        checkAltitude();  // Gọi private method
    }

    // ✅ Static method - có body (Java 8+)
    static void info() {
        System.out.println("Flyable interface");
    }

    // ✅ Private method - code reuse (Java 9+)
    private void checkAltitude() {
        System.out.println("Checking altitude...");
    }

    // ✅ Private static method (Java 9+)
    private static void log(String message) {
        System.out.println("Log: " + message);
    }
}

// ✅ Implementing interface
class Bird implements Flyable {
    @Override
    public void fly() {
        System.out.println("Bird is flying at " + MAX_ALTITUDE);
    }

    // land() được kế thừa từ default method
}

// Test
Bird bird = new Bird();
bird.fly();   // "Bird is flying at 10000"
bird.land();  // "Landing..." + "Checking altitude..."

// ✅ Static method - gọi qua interface name
Flyable.info();  // "Flyable interface"

// ❌ Static method KHÔNG được kế thừa
// Bird.info();  // Compile error!
```

**Interface Fields:**

**Đặc điểm:**
- Mặc định: `public static final` (có thể bỏ qua các từ khóa)
- Phải khởi tạo (do `final`)
- Không thể thay đổi sau khi khởi tạo
- Truy cập qua `InterfaceName.FIELD_NAME`

```java
public interface Config {
    // ✅ Mặc định: public static final
    int MAX_SIZE = 100;
    String APP_NAME = "MyApp";

    // ✅ Các cách khai báo tương đương
    public static final int VALUE1 = 1;
    public static int VALUE2 = 2;
    public final int VALUE3 = 3;
    static final int VALUE4 = 4;
    final int VALUE5 = 5;
    int VALUE6 = 6;

    // ❌ Phải khởi tạo (do final)
    // int INVALID;  // Compile error: blank final field

    // ❌ Không thể có non-final fields
    // int counter = 0;  // Vẫn là final!
}

// ✅ Truy cập constants
System.out.println(Config.MAX_SIZE);  // 100

// ❌ Không thể thay đổi (final)
// Config.MAX_SIZE = 200;  // Compile error!
```

**Multiple Inheritance với Interfaces:**

**Diamond Problem & Resolution:**
- Khi nhiều interfaces có cùng default method → xung đột
- Class phải override method để resolve conflict
- Có thể gọi specific default method: `InterfaceName.super.methodName()`

```java
interface Walkable {
    void walk();

    default void move() {
        System.out.println("Walking...");
    }
}

interface Swimmable {
    void swim();

    default void move() {
        System.out.println("Swimming...");
    }
}

// ❌ Conflict - phải override move()
class Duck implements Walkable, Swimmable {
    @Override
    public void walk() {
        System.out.println("Duck walking");
    }

    @Override
    public void swim() {
        System.out.println("Duck swimming");
    }

    // ✅ Phải override để resolve conflict
    @Override
    public void move() {
        System.out.println("Duck moving");
        // Hoặc gọi specific default:
        // Walkable.super.move();
        // Swimmable.super.move();
    }
}
```

**So sánh Abstract Class vs Interface:**

| Đặc điểm | Abstract Class | Interface |
|----------|----------------|-----------|
| Constructor | ✅ Có | ❌ Không |
| Instance fields | ✅ Có | ❌ Không (chỉ constants) |
| Method types | Abstract, Concrete, Static | Abstract, Default, Static, Private |
| Multiple inheritance | ❌ Không (chỉ extend 1 class) | ✅ Có (implement nhiều interfaces) |
| Access modifiers | ✅ Tất cả | ❌ Chỉ public (và private cho private methods) |
| Static methods inheritance | ✅ Được kế thừa | ❌ Không được kế thừa |
| Khi nào dùng | Khi có shared state/behavior | Khi định nghĩa contract/capability |

**Ví dụ tổng hợp:**

```java
// ✅ Abstract class cho shared implementation
abstract class Vehicle {
    protected String brand;

    public Vehicle(String brand) {
        this.brand = brand;
    }

    public abstract void start();

    public void stop() {
        System.out.println(brand + " stopped");
    }
}

// ✅ Interfaces cho capabilities
interface Electric {
    void charge();

    default void showBatteryLevel() {
        System.out.println("Battery: 100%");
    }
}

interface SelfDriving {
    void enableAutoPilot();
}

// ✅ Kết hợp cả abstract class và multiple interfaces
class Tesla extends Vehicle implements Electric, SelfDriving {
    public Tesla() {
        super("Tesla");
    }

    @Override
    public void start() {
        System.out.println("Tesla started silently");
    }

    @Override
    public void charge() {
        System.out.println("Charging at supercharger");
    }

    @Override
    public void enableAutoPilot() {
        System.out.println("AutoPilot enabled");
    }
}

// Test
Tesla tesla = new Tesla();
tesla.start();            // "Tesla started silently"
tesla.charge();           // "Charging at supercharger"
tesla.showBatteryLevel(); // "Battery: 100%" (default method)
tesla.enableAutoPilot();  // "AutoPilot enabled"
tesla.stop();             // "Tesla stopped" (inherited)
```

---

### 2.5. Overriding Rules (Quy tắc Ghi đè)

**Tóm tắt:**
- Cùng **signature** (tên method + thứ tự/kiểu tham số)
- Access modifier: Bằng hoặc rộng hơn (không được hẹp hơn)
- Return type: Cùng kiểu hoặc subtype (covariant return)
- Exceptions: Cùng, hẹp hơn, hoặc không throws (với checked exceptions)
- `@Override` annotation: Optional nhưng nên dùng để catch lỗi sớm
- Không thể đổi từ instance method ↔ static method

**Ví dụ về Static vs Instance:**

```java
class Parent {
    public static void staticMethod() { }
    public void instanceMethod() { }
}

class Child extends Parent {
    // ❌ Không thể override static bằng instance
    // @Override
    // public void staticMethod() { }  // Compile error

    // ❌ Không thể override instance bằng static
    // @Override
    // public static void instanceMethod() { }  // Compile error

    // ✅ Static method hiding (không phải override)
    public static void staticMethod() {  // Hiding, không override
        System.out.println("Child static");
    }
}
```
---

### 2.6. Inner & Nested Classes

**Tóm tắt:**
- **Member Inner Class**: Non-static class bên trong class khác, cần outer instance
- **Static Nested Class**: Static class bên trong class khác, không cần outer instance
- **Local Class**: Class khai báo trong method/block
- **Anonymous Class**: Class không tên, tạo và sử dụng ngay

---

**1. Member Inner Class:**

**Đặc điểm:**
- Cần outer instance để tạo inner instance
- Có thể truy cập tất cả members của outer (kể cả private)
- Không thể có static members (trừ `static final` constants)

```java
public class Outer {
    private int outerValue = 10;
    private static int staticValue = 20;

    // ✅ Member inner class
    public class Inner {
        private int innerValue = 30;

        // ❌ Không thể có static non-final
        // static int count = 0;  // Compile error

        // ✅ Có thể có static final constant
        static final int MAX = 100;

        public void display() {
            // ✅ Truy cập outer members
            System.out.println("Outer value: " + outerValue);
            System.out.println("Static value: " + staticValue);
            System.out.println("Inner value: " + innerValue);

            // ✅ Tham chiếu tường minh tới outer
            System.out.println("Outer this: " + Outer.this.outerValue);
        }
    }

    public void createInner() {
        Inner inner = new Inner();  // ✅ Tạo từ bên trong outer
        inner.display();
    }
}

// Test
Outer outer = new Outer();
outer.createInner();

// ✅ Tạo inner từ bên ngoài - cần outer instance
Outer.Inner inner = outer.new Inner();
inner.display();

// ❌ Không thể tạo mà không có outer instance
// Outer.Inner invalid = new Outer.Inner();  // Compile error
```

---

**2. Static Nested Class:**

**Đặc điểm:**
- KHÔNG cần outer instance
- Chỉ truy cập được static members của outer
- Có thể có static members
- Giống như class thường, chỉ là nằm trong outer class

```java
public class Outer {
    private int outerValue = 10;
    private static int staticValue = 20;

    // ✅ Static nested class
    public static class StaticNested {
        private int nestedValue = 30;
        private static int staticNestedValue = 40;

        public void display() {
            // ❌ Không truy cập được non-static outer members
            // System.out.println(outerValue);  // Compile error

            // ✅ Truy cập static outer members
            System.out.println("Static value: " + staticValue);
            System.out.println("Nested value: " + nestedValue);
        }

        public static void staticDisplay() {
            System.out.println("Static nested method");
        }
    }
}

// Test - KHÔNG cần outer instance
Outer.StaticNested nested = new Outer.StaticNested();
nested.display();

Outer.StaticNested.staticDisplay();  // Gọi static method
```

---

**3. Local Class:**

**Đặc điểm:**
- Khai báo trong method hoặc block
- Chỉ visible trong scope khai báo
- Có thể truy cập outer members + local variables (phải effectively final)
- Không thể có access modifier hoặc static

```java
public class Outer {
    private int outerValue = 10;

    public void method() {
        final int localFinal = 20;
        int effectivelyFinal = 30;  // Không thay đổi -> effectively final

        // ✅ Local class
        class LocalClass {
            private int localValue = 40;

            public void display() {
                System.out.println("Outer: " + outerValue);
                System.out.println("Local final: " + localFinal);
                System.out.println("Effectively final: " + effectivelyFinal);
                System.out.println("Local: " + localValue);
            }
        }

        // ✅ Sử dụng local class trong scope
        LocalClass local = new LocalClass();
        local.display();

        // effectivelyFinal = 100;  // ❌ Nếu uncomment -> compile error ở trên
    }

    // ❌ Không thể dùng LocalClass ở đây - ngoài scope
    // public void other() {
    //     LocalClass local = new LocalClass();  // Compile error
    // }
}

// Test
Outer outer = new Outer();
outer.method();
```

---

**4. Anonymous Class:**

**Đặc điểm:**
- Không có tên, tạo và sử dụng tại chỗ
- Extends một class HOẶC implements một interface
- Có thể truy cập outer members + effectively final local variables
- Thường dùng cho callback, event handler

```java
// ✅ Interface để demo
interface Greeting {
    void greet(String name);
}

// ✅ Abstract class để demo
abstract class Animal {
    abstract void makeSound();
    void eat() {
        System.out.println("Eating...");
    }
}

public class AnonymousDemo {
    private int outerValue = 10;

    public void demonstrate() {
        final String prefix = "Hello";
        int count = 5;  // Effectively final

        // ✅ Anonymous class implementing interface
        Greeting greeting = new Greeting() {
            @Override
            public void greet(String name) {
                System.out.println(prefix + ", " + name + "!");
                System.out.println("Outer: " + outerValue);
                System.out.println("Count: " + count);
            }
        };
        greeting.greet("World");

        // ✅ Anonymous class extending abstract class
        Animal dog = new Animal() {
            @Override
            void makeSound() {
                System.out.println("Woof!");
            }

            // ✅ Có thể thêm methods/fields mới (nhưng không gọi được từ bên ngoài)
            void specialMethod() {
                System.out.println("Special");
            }
        };
        dog.makeSound();
        dog.eat();
        // dog.specialMethod();  // ❌ Compile error - không visible

        // ✅ Anonymous class extending concrete class
        Thread thread = new Thread() {
            @Override
            public void run() {
                System.out.println("Running in thread");
            }
        };
        thread.start();

        // count = 10;  // ❌ Nếu uncomment -> compile error ở trên
    }
}

// Test
AnonymousDemo demo = new AnonymousDemo();
demo.demonstrate();
```

**So sánh các loại Inner/Nested Classes:**

| Đặc điểm | Member Inner | Static Nested | Local | Anonymous |
|----------|--------------|---------------|-------|-----------|
| Cần outer instance | ✅ | ❌ | ✅ | ✅ |
| Truy cập non-static outer | ✅ | ❌ | ✅ | ✅ |
| Truy cập static outer | ✅ | ✅ | ✅ | ✅ |
| Có static members | ❌ | ✅ | ❌ | ❌ |
| Access modifiers | ✅ | ✅ | ❌ | ❌ |
| Có tên | ✅ | ✅ | ✅ | ❌ |
| Scope | Class-level | Class-level | Method/Block | Inline |

---

### 2.7. Enum

**Tóm tắt:**
- Enum là special class, extends `java.lang.Enum` → không thể extends class khác
- Enum là implicitly `final` → không thể bị extends
- Có thể implement interfaces
- Constructor luôn `private` hoặc package-private
- Mỗi constant là singleton instance, tạo khi class load
- Có thể có fields, methods, constructors như class thường

**Enum cơ bản:**

```java
// ✅ Enum đơn giản
public enum Day {
    MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY;
    // Dấu ; cuối cùng optional nếu không có thêm gì
}

// Test
Day day = Day.MONDAY;
System.out.println(day);  // "MONDAY"

// ✅ Sử dụng trong switch
switch (day) {
    case MONDAY:
        System.out.println("Start of week");
        break;
    case FRIDAY:
        System.out.println("Almost weekend");
        break;
    default:
        System.out.println("Other day");
}
```

**Enum với Constructor, Fields, Methods:**

```java
public enum Size {
    // ✅ Constants với arguments cho constructor
    SMALL("S", 10),
    MEDIUM("M", 20),
    LARGE("L", 30),
    EXTRA_LARGE("XL", 40);  // Dấu ; bắt buộc khi có thêm members

    // ✅ Fields
    private final String code;
    private final int value;

    // ✅ Constructor - luôn private (hoặc package-private)
    private Size(String code, int value) {
        this.code = code;
        this.value = value;
        System.out.println("Creating " + code);  // Chạy khi class load
    }

    // ❌ Constructor không thể public
    // public Size(String code, int value) { }  // Compile error

    // ✅ Getters
    public String getCode() {
        return code;
    }

    public int getValue() {
        return value;
    }

    // ✅ Instance method
    public String getDescription() {
        return code + " (" + value + ")";
    }

    // ✅ Static method
    public static Size fromCode(String code) {
        for (Size size : values()) {
            if (size.code.equals(code)) {
                return size;
            }
        }
        return null;
    }
}

// Test
Size size = Size.MEDIUM;
System.out.println(size.getCode());        // "M"
System.out.println(size.getValue());       // 20
System.out.println(size.getDescription()); // "M (20)"

Size found = Size.fromCode("L");
System.out.println(found);  // LARGE
```

**Built-in Enum Methods:**

```java
public enum Color {
    RED, GREEN, BLUE;
}

// Test
// ✅ values() - trả về array chứa tất cả constants
Color[] colors = Color.values();
for (Color c : colors) {
    System.out.println(c);  // RED, GREEN, BLUE
}

// ✅ valueOf(String) - convert String -> Enum
Color red = Color.valueOf("RED");  // Color.RED
// Color invalid = Color.valueOf("YELLOW");  // IllegalArgumentException

// ✅ name() - trả về tên constant
String name = Color.RED.name();  // "RED"

// ✅ ordinal() - trả về index (từ 0)
int index = Color.RED.ordinal();    // 0
int index2 = Color.GREEN.ordinal(); // 1

// ✅ compareTo() - so sánh theo ordinal
System.out.println(Color.RED.compareTo(Color.BLUE));  // -2 (0 - 2)

// ✅ toString() - mặc định return name()
System.out.println(Color.RED.toString());  // "RED"
```

**Enum với Abstract Methods:**

Mỗi constant phải override abstract method.

```java
public enum Operation {
    // ✅ Mỗi constant override calculate()
    PLUS {
        @Override
        public double calculate(double x, double y) {
            return x + y;
        }
    },
    MINUS {
        @Override
        public double calculate(double x, double y) {
            return x - y;
        }
    },
    MULTIPLY {
        @Override
        public double calculate(double x, double y) {
            return x * y;
        }
    },
    DIVIDE {
        @Override
        public double calculate(double x, double y) {
            if (y == 0) throw new ArithmeticException("Division by zero");
            return x / y;
        }
    };

    // ✅ Abstract method
    public abstract double calculate(double x, double y);
}

// Test
double result1 = Operation.PLUS.calculate(5, 3);      // 8.0
double result2 = Operation.MULTIPLY.calculate(5, 3);  // 15.0
double result3 = Operation.DIVIDE.calculate(10, 2);   // 5.0
```

**Enum Implementing Interface:**

```java
interface Describable {
    String describe();
}

// ✅ Enum implement interface
public enum Planet implements Describable {
    MERCURY(3.303e+23, 2.4397e6),
    VENUS(4.869e+24, 6.0518e6),
    EARTH(5.976e+24, 6.37814e6);

    private final double mass;   // kg
    private final double radius; // m

    private Planet(double mass, double radius) {
        this.mass = mass;
        this.radius = radius;
    }

    public double getMass() {
        return mass;
    }

    public double getRadius() {
        return radius;
    }

    // ✅ Implement interface method
    @Override
    public String describe() {
        return name() + ": mass=" + mass + ", radius=" + radius;
    }

    // ✅ Calculated property
    public double surfaceGravity() {
        final double G = 6.67300E-11;
        return G * mass / (radius * radius);
    }
}

// Test
Planet earth = Planet.EARTH;
System.out.println(earth.describe());
System.out.println("Gravity: " + earth.surfaceGravity());
```

**Enum đặc điểm quan trọng:**

```java
public enum Status {
    ACTIVE, INACTIVE;
}

// ✅ Singleton - mỗi constant là unique instance
Status s1 = Status.ACTIVE;
Status s2 = Status.ACTIVE;
System.out.println(s1 == s2);  // true (cùng instance)

// ❌ Không thể tạo instance bằng new
// Status s = new Status();  // Compile error: no public constructor

// ❌ Enum không thể extends class khác
// public enum MyEnum extends SomeClass { }  // Compile error

// ❌ Enum không thể bị extends
// public class MyClass extends Status { }  // Compile error: final enum

// ✅ Có thể dùng == để so sánh
if (s1 == Status.ACTIVE) {
    System.out.println("Active");
}

// ✅ Enum trong Collections
Set<Status> statuses = EnumSet.of(Status.ACTIVE, Status.INACTIVE);
Map<Status, String> map = new EnumMap<>(Status.class);
map.put(Status.ACTIVE, "Running");
```

---

### 2.8. final & abstract Keywords

**Tóm tắt:**
- `final` class: Không thể bị extends
- `final` method: Không thể bị override
- `final` variable: Chỉ gán 1 lần (constant)
- `abstract` class: Không thể tạo instance, chỉ làm base class
- `abstract` method: Không có body, subclass phải implement

---

**final Class:**

```java
// ✅ final class - không thể bị extends
public final class FinalClass {
    public void method() {
        System.out.println("Final class method");
    }
}

// ❌ Không thể extends final class
// class SubClass extends FinalClass { }  // Compile error: cannot inherit from final

// ✅ Examples: String, Integer, Math đều là final classes
// class MyString extends String { }  // Compile error
```

**final Method:**

```java
class Parent {
    // ✅ final method - không thể override
    public final void finalMethod() {
        System.out.println("Final method");
    }

    public void normalMethod() {
        System.out.println("Normal method");
    }
}

class Child extends Parent {
    // ❌ Không thể override final method
    // @Override
    // public void finalMethod() { }  // Compile error: cannot override

    // ✅ Có thể override non-final method
    @Override
    public void normalMethod() {
        System.out.println("Overridden");
    }
}
```

**final Variable:**

```java
public class FinalVariableDemo {
    // ✅ final instance variable - phải khởi tạo
    private final int CONSTANT1 = 10;  // Khởi tạo khi khai báo
    private final int CONSTANT2;        // Khởi tạo trong constructor

    // ✅ final static variable - class constant
    public static final double PI = 3.14159;
    private static final int MAX_SIZE;

    // ✅ Static initializer block
    static {
        MAX_SIZE = 100;
    }

    // ✅ Constructor khởi tạo final field
    public FinalVariableDemo(int value) {
        CONSTANT2 = value;  // ✅ OK - lần đầu gán
        // CONSTANT2 = value + 1;  // ❌ Compile error: variable might already have been assigned
    }

    public void method() {
        // ✅ final local variable
        final int localFinal = 20;
        // localFinal = 30;  // ❌ Compile error: cannot assign

        // ✅ Effectively final (Java 8+)
        int effectivelyFinal = 40;
        Runnable r = () -> System.out.println(effectivelyFinal);  // OK
        // effectivelyFinal = 50;  // ❌ Nếu uncomment -> compile error ở trên

        // ✅ final reference - object có thể thay đổi, nhưng reference không
        final StringBuilder sb = new StringBuilder("Hello");
        sb.append(" World");  // ✅ OK - thay đổi object
        // sb = new StringBuilder();  // ❌ Compile error: cannot assign
    }

    // ❌ final variable phải được khởi tạo
    // private final int UNINITIALIZED;  // Compile error nếu không init trong constructor
}

// Test
FinalVariableDemo.PI = 3.14;  // ❌ Compile error: cannot assign to final
```

**abstract Class:**

```java
// ✅ abstract class
public abstract class Animal {
    private String name;

    // ✅ Constructor
    public Animal(String name) {
        this.name = name;
    }

    // ✅ Abstract method - không có body
    public abstract void makeSound();

    // ✅ Concrete method
    public void eat() {
        System.out.println(name + " is eating");
    }

    // ✅ Có thể có static method
    public static void info() {
        System.out.println("Animal class");
    }
}

// ✅ Concrete subclass phải implement abstract methods
class Dog extends Animal {
    public Dog(String name) {
        super(name);
    }

    @Override
    public void makeSound() {
        System.out.println("Woof!");
    }
}

// ✅ Abstract subclass không cần implement
abstract class Bird extends Animal {
    public Bird(String name) {
        super(name);
    }
    // Không implement makeSound() - OK vì Bird cũng abstract
}

// ❌ Không thể instantiate abstract class
// Animal a = new Animal("Test");  // Compile error

// ✅ Có thể tạo instance của concrete subclass
Animal dog = new Dog("Buddy");
dog.makeSound();  // "Woof!"
dog.eat();        // "Buddy is eating"
```

**abstract Method:**

```java
abstract class Shape {
    // ✅ abstract method
    public abstract double calculateArea();

    // ✅ Có thể có concrete method
    public void display() {
        System.out.println("Area: " + calculateArea());
    }
}

class Circle extends Shape {
    private double radius;

    public Circle(double radius) {
        this.radius = radius;
    }

    // ✅ Phải implement abstract method
    @Override
    public double calculateArea() {
        return Math.PI * radius * radius;
    }
}

// ❌ Nếu không implement -> phải là abstract
// class Rectangle extends Shape {
//     // Compile error: Rectangle is not abstract and does not override calculateArea()
// }

// ✅ Hoặc khai báo là abstract
abstract class Rectangle extends Shape {
    // OK - không cần implement vì Rectangle cũng abstract
}
```

---

**Các tổ hợp KHÔNG HỢP LỆ:**

```java
// ❌ abstract final class - CONFLICT!
// abstract: cần được extends
// final: không thể extends
// abstract final class InvalidClass { }  // Compile error

// ❌ abstract final method - CONFLICT!
abstract class MyClass {
    // abstract: cần được override
    // final: không thể override
    // public abstract final void method();  // Compile error
}

// ❌ abstract private method - CONFLICT!
abstract class MyClass2 {
    // abstract: cần được override
    // private: không thể override (không visible trong subclass)
    // private abstract void method();  // Compile error
}

// ❌ abstract static method - CONFLICT!
abstract class MyClass3 {
    // abstract: cần được override
    // static: không thể override (chỉ hiding)
    // public static abstract void method();  // Compile error
}

// ❌ final + abstract instance variable - KHÓ HIỂU
// final variable trong abstract class OK, nhưng cần init
abstract class MyClass4 {
    // ✅ OK - nhưng mỗi subclass sẽ có cùng giá trị
    final int value = 10;

    // ❌ Không thể abstract variable
    // abstract int value2;  // Compile error: illegal combination of modifiers
}
```

**Ví dụ thực tế kết hợp final & abstract:**

```java
// ✅ abstract class với final method
public abstract class BaseProcessor {
    // ✅ Template method pattern - final để prevent override
    public final void process() {
        initialize();
        doProcess();
        cleanup();
    }

    // ✅ Abstract methods - subclass must implement
    protected abstract void initialize();
    protected abstract void doProcess();
    protected abstract void cleanup();
}

class FileProcessor extends BaseProcessor {
    @Override
    protected void initialize() {
        System.out.println("Opening file");
    }

    @Override
    protected void doProcess() {
        System.out.println("Processing file");
    }

    @Override
    protected void cleanup() {
        System.out.println("Closing file");
    }

    // ❌ Không thể override process()
    // public void process() { }  // Compile error: cannot override final
}

// Test
BaseProcessor processor = new FileProcessor();
processor.process();
// Output:
// Opening file
// Processing file
// Closing file
```

**Tóm tắt Conflicts:**

| Tổ hợp | Hợp lệ? | Lý do |
|--------|---------|-------|
| `final` class | ✅ | Prevent inheritance |
| `abstract` class | ✅ | Cannot instantiate |
| `final abstract` class | ❌ | **CONFLICT**: abstract cần extends, final không cho extends |
| `final` method | ✅ | Prevent override |
| `abstract` method | ✅ | Must be implemented |
| `final abstract` method | ❌ | **CONFLICT**: abstract cần override, final không cho override |
| `abstract private` method | ❌ | **CONFLICT**: abstract cần visible để override |
| `abstract static` method | ❌ | **CONFLICT**: static không thể override |
| `final` variable | ✅ | Constant |
| `abstract` variable | ❌ | **KHÔNG TỒN TẠI**: variables không có abstract |

---

## 3. Control Flow

### 3.1. for Loop

**Tóm tắt:**
- **Standard for loop**: `for(init; condition; update) { }`
- **Enhanced for loop**: `for(type var : collection) { }`
- Enhanced loop chỉ dùng với arrays, Collections, hoặc Iterable
- Map không phải Iterable → dùng `Map.entrySet()`, `keySet()`, hoặc `values()`

**Standard for Loop:**

```java
// ✅ Multiple variables trong for loop
for (int i = 0, j = 10; i < 5; i++, j--) {
    System.out.println(i + " " + j);  // 0 10, 1 9, 2 8, 3 7, 4 6
}

// ❌ Variables phải cùng type
// for (int i = 0, long j = 0; i < 5; i++) { }  // Compile error

// ✅ Infinite loop
for (;;) {
    if (condition) break;  // Cần break để thoát
}
```

**Enhanced for Loop (for-each):**

```java
List<String> names = List.of("Alice", "Bob", "Charlie");

// ✅ Sử dụng var (Java 10+)
for (var name : names) {
    System.out.println(name);  // var inferred as String
}

// ❌ Không thể dùng biến đã khai báo - phải khai báo trong for
String item;
// for (item : names) { }  // Compile error: must declare variable
for (String item2 : names) { }  // ✅ OK
```

**Enhanced Loop với Map:**

```java
Map<String, Integer> scores = Map.of("Alice", 90, "Bob", 85, "Charlie", 95);

// ❌ Map không implement Iterable
// for (var entry : scores) { }  // Compile error

// ✅ Dùng entrySet()
for (Map.Entry<String, Integer> entry : scores.entrySet()) {
    System.out.println(entry.getKey() + ": " + entry.getValue());
}

// ✅ Dùng keySet()
for (String key : scores.keySet()) {
    System.out.println(key + ": " + scores.get(key));
}

// ✅ Dùng values()
for (Integer value : scores.values()) {
    System.out.println(value);
}

// ✅ Với var
for (var entry : scores.entrySet()) {
    System.out.println(entry.getKey() + ": " + entry.getValue());
}
```

**Lưu ý về Enhanced Loop:**

```java
List<Integer> numbers = new ArrayList<>(List.of(1, 2, 3, 4, 5));

// ❌ Không thể modify collection trong enhanced loop
for (Integer num : numbers) {
    if (num == 3) {
        // numbers.remove(num);  // ConcurrentModificationException!
    }
}

// ✅ Dùng Iterator để modify
Iterator<Integer> it = numbers.iterator();
while (it.hasNext()) {
    Integer num = it.next();
    if (num == 3) {
        it.remove();  // OK
    }
}

// ✅ Hoặc dùng removeIf (Java 8+)
numbers.removeIf(num -> num == 3);
```

---

### 3.2. switch Statement

**Tóm tắt:**
- Kiểu hợp lệ: `byte`, `short`, `char`, `int`, `String`, `enum`, và wrapper types
- Chỉ có 1 `default`, vị trí tùy ý
- **Fall-through**: Không có `break` → tiếp tục case tiếp theo
- Case values phải là **compile-time constants**
- Không được duplicate case values => compile error

**Các kiểu hợp lệ:**

```java
// ✅ Kiểu nguyên thủy: byte, short, char, int (và wrapper tương ứng)
int dayNumber = 1;
char c = 'A';
Integer num = 1;
switch (dayNumber) { case 1: break; }
switch (c) { case 'A': break; }
switch (num) { case 1: break; }

// ✅ String (Java 7+)
String day = "Monday";
switch (day) {
    case "Monday": System.out.println("Start of week"); break;
    case "Friday": System.out.println("Almost weekend"); break;
}

// ✅ Enum - không cần prefix tên enum
enum Day { MONDAY, TUESDAY, WEDNESDAY }
Day today = Day.MONDAY;
switch (today) {
    case MONDAY:  // ✅ Không cần Day.MONDAY
        System.out.println("Monday");
        break;
}

// ❌ Các kiểu KHÔNG hợp lệ: long, float, double, boolean
// switch (1L) { }        // Compile error
// switch (1.0) { }       // Compile error
// switch (true) { }      // Compile error
```

**Empty Switch:**

```java
// ✅ Empty switch - hợp lệ
int value = 5;
switch (value) {
    // Không làm gì
}

// ✅ Switch chỉ có default
switch (value) {
    default:
        System.out.println("Default");
}
```

**Fall-through:**

```java
int month = 2;
int days = 0;

switch (month) {
    case 1: case 3: case 5: case 7: case 8: case 10: case 12:
        days = 31;
        break;
    case 4: case 6: case 9: case 11:
        days = 30;
        break;
    case 2:
        days = 28;  // hoặc 29
        break;
    default:
        System.out.println("Invalid month");
}

// ✅ Fall-through có chủ đích
int score = 85;
switch (score / 10) {
    case 10:
    case 9:
        System.out.println("A");
        break;
    case 8:
        System.out.println("B");
        break;
    case 7:
        System.out.println("C");
        break;
    default:
        System.out.println("F");
}

// ⚠️ Fall-through không chủ đích - dễ lỗi
int day = 1;
switch (day) {
    case 1:
        System.out.println("Monday");
        // Thiếu break → fall-through!
    case 2:
        System.out.println("Tuesday");
        break;
}
// Output:
// Monday
// Tuesday
```

**default Position:**

```java
// ✅ default có thể ở bất kỳ đâu (đầu, giữa, cuối)
switch (value) {
    default: System.out.println("Default"); break;
    case 1: break;
    case 2: break;
}

// ❌ Chỉ được 1 default
// switch (value) {
//     default: break;
//     default: break;  // Compile error: duplicate default label
// }
```

**Case Values phải là Constants:**

```java
final int CONST = 10;
int variable = 20;

switch (value) {
    case 5:           // ✅ Literal
        break;
    case CONST:       // ✅ Final variable (compile-time constant)
        break;
    // case variable: // ❌ Compile error: constant expression required
    //     break;
}

// ❌ Duplicate case values
// switch (value) {
//     case 1: break;
//     case 1: break;  // Compile error: duplicate case label
// }
```

**Switch với String null:**

```java
String text = null;

// ⚠️ NullPointerException
switch (text) {  // Runtime error: NullPointerException
    case "Hello": break;
}

// ✅ Cần check null trước
if (text != null) {
    switch (text) {
        case "Hello": break;
    }
}
```

---

### 3.3. Labels, break, và continue

**Tóm tắt:**
- **Label**: Tên đặt cho statement hoặc block
- **break**: Thoát khỏi loop hoặc switch gần nhất (hoặc labeled block)
- **continue**: Skip phần còn lại của iteration hiện tại
- `break` + label: Thoát khỏi labeled block/loop
- `continue` + label: Skip đến iteration tiếp theo của labeled loop

**Labels:**

```java
// ✅ Label cho loop hoặc block
outerLoop: for (int i = 0; i < 3; i++) { }

myBlock: {
    if (condition) break myBlock;  // Thoát block
}

// ❌ Không thể label một statement đơn
// myLabel: x = 10;  // Compile error
```

**break (không có label):**

```java
// ✅ break chỉ thoát loop/switch gần nhất
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) {
            break;  // Chỉ thoát inner loop
        }
        System.out.print(i + "," + j + " ");
    }
}
// Output: 0,0 1,0 2,0
```

**break với label:**

```java
// ✅ break outer loop
outer:
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == 1 && j == 1) {
            break outer;  // Thoát outer loop
        }
        System.out.println(i + "," + j);
    }
}
// Output:
// 0,0
// 0,1
// 0,2
// 1,0

// ❌ Label phải là block hoặc loop
// single: System.out.println("Single statement");
// break single;  // Compile error: undefined label
```

**continue (không có label):**

```java
// ✅ continue chỉ skip iteration hiện tại của loop gần nhất
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) {
            continue;  // Skip j = 1 trong inner loop
        }
        System.out.print(i + "," + j + " ");
    }
}
// Output: 0,0 0,2 1,0 1,2 2,0 2,2
```

**continue với label:**

```java
// ✅ continue outer loop
outer:
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) {
            continue outer;  // Skip đến iteration tiếp theo của outer
        }
        System.out.println(i + "," + j);
    }
    System.out.println("End of outer iteration");  // Không chạy
}
// Output:
// 0,0
// 1,0
// 2,0

// ❌ continue phải dùng với loop
// myBlock: {
//     continue myBlock;  // Compile error: continue cannot be used outside of a loop
// }

// ❌ Label phải là loop
// notLoop: System.out.println("Statement");
// for (int i = 0; i < 5; i++) {
//     continue notLoop;  // Compile error: undefined label
// }
```
---

## 4. Arrays & Collections

### 4.1. Arrays

- Mảng có kích thước cố định, không thay đổi sau khi tạo, dùng `.length` (field, không phải method `.length()`)
- Arrays utility class (java.util.Arrays)
  - **sort(arr)** hoặc **sort(arr, Comparator)**: sắp xếp tăng dần (natural order), không trả về mảng mới, thay đổi trực tiếp.
  - **binarySearch(arr, key)** hoặc **binarySearch(arr, key, Comparator)**: tìm index trong mảng đã sort, nếu không tìm thấy, trả về -(insertion_point)-1
    - insertion_point: vị trí cần chèn key vào để mảng giữ thứ tự
    - Công thức: `insertion_point = -result - 1`
  - **equals(a, b)**: so sánh 2 mảng 1D theo từng phần tử. Trả về true nếu cùng length và tất cả các phần tử bằng nhau.

  ```java
  int[] a = {1, 2, 3};
  int[] b = {1, 2, 3};
  Arrays.equals(a, b);  // true
  ```

  - **deepEquals(a, b)**: dùng cho mảng nhiều chiều hoặc mảng các object, so sánh đệ quy thay vì so sánh địa chỉ.

  ```java
  int[][] m1 = {% raw %}{{1, 2}, {3, 4}}{% endraw %};
  int[][] m2 = {% raw %}{{1, 2}, {3, 4}}{% endraw %};
  Arrays.deepEquals(m1, m2);  // true
  ```

  - **mismatch(a, b)**: so sánh 2 mảng theo từng phần tử, trả về index đầu tiên khác nhau, nếu giống nhau hoàn toàn trả về -1.

  ```java
  int[] x = {1, 2, 3, 4};
  int[] y = {1, 2, 9, 4};
  Arrays.mismatch(x, y);  // 2
  ```

  - **compare(a, b)**: so sánh lexicographically (từ điển), trả về âm/0/dương

**ragged array**
- mảng có độ dài mỗi hàng khác nhau
- Các array bên trong cần khởi tạo riêng nếu sử dụng.

```java
int[][] ragged = new int[3][];
ragged[0] = new int[2];  // {0, 0}
ragged[1] = new int[4];  // {0, 0, 0, 0}
ragged[2] = new int[3];  // {0, 0, 0}
```

**System.arraycopy(src, srcPos, dest, destPos, length)**
- Copy elements từ mảng nguồn sang mảng đích
- Nếu length vượt quá src.length hoặc dest.length => throw ArrayIndexOutOfBoundsException (Runtime Exception)

**Arrays.copyOf(arr, newLength)**
- Tạo mảng mới với độ dài newLength
- Nếu newLength > arr.length, thêm giá trị mặc định (0, null, false...)
- Nếu newLength < arr.length, cắt bớt

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ Khai báo sai
int[] a1 = new int[];        // Compile error: phải có size
int[] a2 = new int[3]{1,2,3}; // Compile error: không được vừa size vừa initializer

// ✅ Khai báo đúng
int[] a3 = new int[3];
int[] a4 = {1, 2, 3};
int[] a5 = new int[]{1, 2, 3};

// ⚠️ Array reference comparison
int[] x = {1, 2, 3};
int[] y = {1, 2, 3};
x == y;              // false (khác reference)
x.equals(y);         // false (equals() từ Object, so sánh reference)
Arrays.equals(x, y); // true (so sánh nội dung)

// ⚠️ binarySearch trên mảng CHƯA sort
int[] arr = {3, 1, 4, 2};
Arrays.binarySearch(arr, 2);  // Kết quả KHÔNG đảm bảo đúng!

// ✅ Phải sort trước
Arrays.sort(arr);  // [1, 2, 3, 4]
Arrays.binarySearch(arr, 2);  // 1 (đúng)

// ⚠️ ArrayIndexOutOfBoundsException
int[] nums = new int[3];
nums[3] = 10;  // Runtime error: index 3 out of bounds for length 3

// ⚠️ NullPointerException với mảng
int[] nullArr = null;
nullArr.length;  // NullPointerException
nullArr[0] = 5;  // NullPointerException

// ⚠️ Ragged array - phần tử chưa khởi tạo
int[][] ragged = new int[3][];
ragged[0][0] = 1;  // NullPointerException (ragged[0] chưa được khởi tạo)
```

---

### 4.2. Collections (java.util)

- Các interface chính: List, Set, Queue, Deque, Map

**List (ordered, cho phép duplicate)**
- Các implement thường dùng: **ArrayList**, **LinkedList**, Vector, Stack
- Các method thường dùng: add, get, set, remove, size(), indexOf, subList(from, to)
- Stack (extends Vector): push, pop, peek
- **List.of(...)**: trả về **immutable** list (không add, remove, set), không nhận giá trị null

```java
List<String> list = List.of("A", "B", "C");
// list.add("D");  // ❌ UnsupportedOperationException
```

- **List.copyOf(collection)**: trả về immutable list, nếu tham số đã là immutable, trả về luôn tham số (không copy)
- **Constructor nhận Collection**: shallow copy các phần tử hiện có (sao chép reference đến object)

```java
List<String> original = new ArrayList<>(List.of("A", "B"));
List<String> copy = new ArrayList<>(original);  // shallow copy
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ List.of() không nhận null
List<String> list1 = List.of("A", null, "C");  // NullPointerException

// ❌ List.of() là immutable
List<String> list2 = List.of("A", "B");
list2.add("C");      // UnsupportedOperationException
list2.set(0, "X");   // UnsupportedOperationException
list2.remove(0);     // UnsupportedOperationException

// ⚠️ Arrays.asList() - fixed-size nhưng có thể set
List<String> list3 = Arrays.asList("A", "B", "C");
list3.set(0, "X");   // ✅ OK
list3.add("D");      // ❌ UnsupportedOperationException
list3.remove(0);     // ❌ UnsupportedOperationException

// ⚠️ ArrayList constructor vs List.of()
List<String> list4 = new ArrayList<>(List.of("A", "B"));
list4.add("C");      // ✅ OK (ArrayList là mutable)

// ⚠️ subList() returns view, không phải copy
List<Integer> original = new ArrayList<>(List.of(1, 2, 3, 4, 5));
List<Integer> sub = original.subList(1, 3);  // [2, 3] - VIEW
sub.set(0, 10);      // original = [1, 10, 3, 4, 5]
original.add(6);     // ConcurrentModificationException khi dùng sub sau đó

// ⚠️ remove() method overload
List<Integer> nums = new ArrayList<>(List.of(1, 2, 3, 4));
nums.remove(1);           // Remove tại index 1 → [1, 3, 4]
nums.remove(Integer.valueOf(3));  // Remove object 3 → [1, 4]
```

---

**Set (không duplicate)**
- Các implement thường dùng: **HashSet**, **LinkedHashSet**, **TreeSet**
- **HashSet**: không giữ thứ tự, cho phép null
- **LinkedHashSet**: giữ các phần tử theo thứ tự chèn, cho phép null
- **TreeSet**: giữ theo natural order hoặc Comparator, **không** cho phép phần tử null (do cần so sánh bằng compareTo/Comparator)
- **Set.of(...)**: tương tự List.of(), trả về immutable set, không nhận null

**NavigableSet (extends SortedSet)**
- Interface cung cấp các method tìm kiếm gần một phần tử nào đó
- **TreeSet implements NavigableSet**

```java
NavigableSet<Integer> set = new TreeSet<>(Set.of(1, 5, 10, 15));
set.lower(10);     // 5 (< 10)
set.floor(10);     // 10 (<= 10)
set.ceiling(10);   // 10 (>= 10)
set.higher(10);    // 15 (> 10)
set.descendingSet();  // Reverse order view
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ TreeSet không cho phép null
TreeSet<String> tree = new TreeSet<>();
tree.add(null);  // NullPointerException

// ✅ HashSet cho phép null
HashSet<String> hash = new HashSet<>();
hash.add(null);  // OK

// ⚠️ Set không có get() method
Set<String> set = new HashSet<>(Set.of("A", "B", "C"));
// set.get(0);  // Compile error: no such method

// ⚠️ Set.of() không cho phép duplicate
Set<String> set1 = Set.of("A", "B", "A");  // IllegalArgumentException

// ✅ Add vào Set trả về boolean
Set<String> set2 = new HashSet<>();
set2.add("A");  // true (added)
set2.add("A");  // false (already exists)

// ⚠️ TreeSet yêu cầu comparable hoặc Comparator
class Person { String name; }
Set<Person> people = new TreeSet<>();
people.add(new Person());  // ClassCastException (Person không implements Comparable)

// ✅ Cần Comparator
Set<Person> people2 = new TreeSet<>((p1, p2) -> p1.name.compareTo(p2.name));

// ⚠️ NavigableSet methods trả về null nếu không tìm thấy
NavigableSet<Integer> nums = new TreeSet<>(Set.of(5, 10, 15));
nums.lower(5);    // null (không có phần tử < 5)
nums.higher(15);  // null (không có phần tử > 15)
```

---

**Queue (FIFO - First In First Out)**
- Hàng đợi 1 đầu
- Các method thường dùng:

| Method | Throws Exception | Returns Special Value |
|--------|------------------|----------------------|
| Insert | add(e) | offer(e) |
| Remove | remove() | poll() |
| Examine | element() | peek() |

```java
Queue<String> queue = new LinkedList<>();
queue.offer("A");  // true
queue.peek();      // "A" (không remove)
queue.poll();      // "A" (remove và return)
```

---

**Deque (Double-Ended Queue)**
- Hàng đợi 2 đầu (có thể thêm/xóa từ cả 2 đầu)
- Các implement chính: **ArrayDeque**, **LinkedList**
- Các method: 2 nhóm hành vi (throw exception / return special value) × 2 đầu (First/Last)

```java
Deque<String> deque = new ArrayDeque<>();
deque.offerFirst("A");  // Thêm vào đầu
deque.offerLast("B");   // Thêm vào cuối
deque.pollFirst();      // "A"
deque.pollLast();       // "B"
```

---

**PriorityQueue**
- Phần tử đầu hàng luôn là phần tử nhỏ nhất theo natural order hoặc Comparator
- Có thể chứa phần tử trùng
- **Không** cho phép null

```java
PriorityQueue<Integer> pq = new PriorityQueue<>();
pq.offer(5);
pq.offer(2);
pq.offer(8);
pq.poll();  // 2 (phần tử nhỏ nhất)
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ⚠️ Queue methods - exception vs return special value
Queue<String> q = new LinkedList<>();

// Empty queue
q.remove();   // NoSuchElementException
q.poll();     // null

q.element();  // NoSuchElementException
q.peek();     // null

// ⚠️ PriorityQueue không cho phép null
PriorityQueue<Integer> pq = new PriorityQueue<>();
pq.offer(null);  // NullPointerException

// ⚠️ PriorityQueue KHÔNG đảm bảo thứ tự khi iterate
PriorityQueue<Integer> pq2 = new PriorityQueue<>();
pq2.offer(5);
pq2.offer(2);
pq2.offer(8);
// Iterator có thể cho: 2, 5, 8 HOẶC 2, 8, 5 (không đảm bảo)
// CHỈ đầu hàng (peek/poll) luôn đúng

// ⚠️ Deque như Stack
Deque<String> stack = new ArrayDeque<>();
stack.push("A");   // Thêm vào đầu
stack.push("B");
stack.pop();       // "B" (LIFO)
stack.peek();      // "A"
```

---

## 5. Collections Utility Class

Các method thường dùng trong **java.util.Collections**:

```java
List<Integer> list = new ArrayList<>(List.of(3, 1, 4, 1, 5));

// ✅ sort() - sắp xếp
Collections.sort(list);  // [1, 1, 3, 4, 5]

// ✅ binarySearch() - tìm kiếm (list phải đã sort)
int index = Collections.binarySearch(list, 3);  // 2

// ✅ reverse() - đảo ngược
Collections.reverse(list);  // [5, 4, 3, 1, 1]

// ✅ shuffle() - xáo trộn
Collections.shuffle(list);

// ✅ max(), min()
Collections.max(list);  // 5
Collections.min(list);  // 1

// ✅ frequency() - đếm số lần xuất hiện
Collections.frequency(list, 1);  // 2

// ✅ copy(dest, src) - copy list
List<Integer> dest = new ArrayList<>(Arrays.asList(0, 0, 0, 0, 0));
Collections.copy(dest, List.of(1, 2, 3));  // dest = [1, 2, 3, 0, 0]
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ⚠️ Collections.copy() yêu cầu dest.size() >= src.size()
List<Integer> small = new ArrayList<>();
Collections.copy(small, List.of(1, 2, 3));  // IndexOutOfBoundsException

// ✅ Phải có đủ size
List<Integer> big = new ArrayList<>(Arrays.asList(0, 0, 0));
Collections.copy(big, List.of(1, 2, 3));  // OK

// ⚠️ Collections.sort() chỉ dùng với List (không phải Set)
Set<Integer> set = new HashSet<>(Set.of(3, 1, 2));
// Collections.sort(set);  // Compile error: requires List

// ⚠️ binarySearch yêu cầu list đã sort
List<Integer> list = new ArrayList<>(List.of(3, 1, 4, 2));
Collections.binarySearch(list, 2);  // Kết quả KHÔNG đúng

Collections.sort(list);  // Phải sort trước
Collections.binarySearch(list, 2);  // OK
```

---

### 5.1. Map

- **Map không extends Collection interface**
- Các implement hay gặp: **HashMap**, **TreeMap**, **LinkedHashMap**
- **HashMap**: không giữ thứ tự, cho phép null key (1 lần) và null values
- **TreeMap**: giữ theo natural order hoặc Comparator, **không** cho phép null key
- **LinkedHashMap**: giữ thứ tự chèn

**Các method cơ bản:**

```java
Map<String, Integer> map = new HashMap<>();
map.put("A", 1);           // Thêm/cập nhật
map.get("A");              // 1
map.containsKey("A");      // true
map.containsValue(1);      // true
map.remove("A");           // Xóa và return value
map.keySet();              // Set<String>
map.values();              // Collection<Integer>
map.entrySet();            // Set<Map.Entry<String, Integer>>
```

**Map factory methods (Java 9+):**

```java
// ✅ Map.of() - immutable map, không nhận null
Map<String, Integer> map = Map.of("A", 1, "B", 2, "C", 3);

// ✅ Map.ofEntries() - dùng khi > 10 entries
Map<String, Integer> map2 = Map.ofEntries(
    Map.entry("A", 1),
    Map.entry("B", 2)
);
```

**NavigableMap (TreeMap implements NavigableMap):**

```java
NavigableMap<Integer, String> map = new TreeMap<>();
map.put(1, "One");
map.put(5, "Five");
map.put(10, "Ten");

map.lowerKey(5);     // 1 (< 5)
map.floorKey(5);     // 5 (<= 5)
map.ceilingKey(5);   // 5 (>= 5)
map.higherKey(5);    // 10 (> 5)
map.descendingMap(); // Reverse order view
```

**Advanced methods (Java 8+):**

```java
Map<String, Integer> map = new HashMap<>();

// ✅ getOrDefault
map.getOrDefault("X", 0);  // 0 (key không tồn tại)

// ✅ putIfAbsent - chỉ put nếu key chưa tồn tại
map.putIfAbsent("A", 1);   // put
map.putIfAbsent("A", 2);   // không put (key đã tồn tại)

// ✅ replace
map.replace("A", 10);      // Thay giá trị nếu key tồn tại
map.replace("A", 1, 20);   // Thay nếu key=A và oldValue=1

// ✅ replaceAll(BiFunction)
map.replaceAll((k, v) -> v * 2);  // Nhân đôi tất cả values

// ✅ computeIfAbsent - tính value nếu key chưa tồn tại
map.computeIfAbsent("B", k -> k.length());  // put("B", 1)

// ✅ computeIfPresent - tính lại value nếu key tồn tại
map.computeIfPresent("A", (k, v) -> v + 1);  // Tăng value lên 1

// ✅ merge - merge value
map.merge("A", 5, (oldVal, newVal) -> oldVal + newVal);
// Nếu key tồn tại: value = oldVal + newVal
// Nếu key chưa tồn tại: value = newVal
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ Map.of() không nhận null key hoặc null value
Map<String, Integer> map1 = Map.of("A", null);      // NullPointerException
Map<String, Integer> map2 = Map.of(null, 1);        // NullPointerException

// ❌ Map.of() không cho phép duplicate keys
Map<String, Integer> map3 = Map.of("A", 1, "A", 2); // IllegalArgumentException

// ❌ Map.of() là immutable
Map<String, Integer> map4 = Map.of("A", 1);
map4.put("B", 2);  // UnsupportedOperationException

// ✅ HashMap cho phép 1 null key và nhiều null values
Map<String, Integer> hash = new HashMap<>();
hash.put(null, 1);      // OK
hash.put("A", null);    // OK
hash.put("B", null);    // OK

// ❌ TreeMap không cho phép null key
Map<String, Integer> tree = new TreeMap<>();
tree.put(null, 1);  // NullPointerException
tree.put("A", null); // ✅ OK (null value được phép)

// ⚠️ put() trả về old value (hoặc null)
Map<String, Integer> map = new HashMap<>();
map.put("A", 1);  // null (key chưa tồn tại)
map.put("A", 2);  // 1 (trả về old value)

// ⚠️ remove() trả về value (hoặc null)
map.remove("A");  // 2 (trả về value)
map.remove("X");  // null (key không tồn tại)

// ⚠️ keySet(), values(), entrySet() là VIEW
Map<String, Integer> m = new HashMap<>(Map.of("A", 1, "B", 2));
Set<String> keys = m.keySet();
keys.remove("A");  // m cũng bị xóa key "A"

// ⚠️ Iterate Map
Map<String, Integer> map = new HashMap<>(Map.of("A", 1, "B", 2));

// ❌ Map không phải Iterable
// for (var entry : map) { }  // Compile error

// ✅ Dùng entrySet()
for (Map.Entry<String, Integer> entry : map.entrySet()) {
    entry.getKey();
    entry.getValue();
}

// ⚠️ merge() với null result
map.merge("A", 10, (old, newVal) -> null);  // Remove key "A"

// ⚠️ computeIfPresent() với null result
map.computeIfPresent("B", (k, v) -> null);  // Remove key "B"

// ⚠️ NavigableMap methods trả về null nếu không tìm thấy
NavigableMap<Integer, String> nav = new TreeMap<>();
nav.put(5, "Five");
nav.lowerKey(5);   // null (không có key < 5)
nav.higherKey(5);  // null (không có key > 5)
```

---
## 6. Exception Handling

**Sơ đồ kế thừa Exception:**

```
java.lang.Object
    └── java.lang.Throwable
            ├── java.lang.Exception (Checked)
            │       ├── IOException
            │       ├── SQLException
            │       ├── FileNotFoundException
            │       ├── ClassNotFoundException
            │       └── java.lang.RuntimeException (Unchecked)
            │               ├── NullPointerException
            │               ├── ArrayIndexOutOfBoundsException
            │               ├── IllegalArgumentException
            │               ├── NumberFormatException
            │               ├── ClassCastException
            │               ├── ArithmeticException
            │               └── UnsupportedOperationException
            └── java.lang.Error (Unchecked)
                    ├── OutOfMemoryError
                    ├── StackOverflowError
                    └── ExceptionInInitializerError
```

---

### 6.1. Exception Types

**Checked Exception:**
- Extends Exception (KHÔNG phải RuntimeException)
- **Bắt buộc** xử lý bằng try-catch hoặc khai báo throws
- Compiler kiểm tra tại compile time
- Thường là lỗi có thể recover (file không tồn tại, network timeout...)

```java
// ❌ Compile error: unhandled exception
public void readFile() {
    FileReader fr = new FileReader("file.txt");  // IOException
}

// ✅ Xử lý bằng try-catch
public void readFile() {
    try {
        FileReader fr = new FileReader("file.txt");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// ✅ Hoặc khai báo throws
public void readFile() throws IOException {
    FileReader fr = new FileReader("file.txt");
}
```

**Unchecked Exception (RuntimeException):**
- Extends RuntimeException
- **Không bắt buộc** xử lý (có thể catch nếu muốn)
- Không cần khai báo throws
- Thường là lỗi lập trình (null pointer, array out of bounds...)

```java
// ✅ Không cần try-catch hoặc throws
public void divide(int a, int b) {
    int result = a / b;  // Có thể throw ArithmeticException
}

// ✅ Có thể catch nếu cần
public void divide(int a, int b) {
    try {
        int result = a / b;
    } catch (ArithmeticException e) {
        System.out.println("Cannot divide by zero");
    }
}
```

**Error:**
- Extends Error
- Lỗi nghiêm trọng của JVM/môi trường (OutOfMemoryError, StackOverflowError...)
- **Unchecked** - không bắt buộc xử lý
- Thường **KHÔNG nên** catch (không thể recover)

```java
// ⚠️ Không nên catch Error
try {
    // code
} catch (OutOfMemoryError e) {  // Không khuyến khích
    // Không thể làm gì nhiều
}
```

---

### 6.2. Try-Catch-Finally

**Cú pháp:**
- try phải đi cùng **catch** HOẶC **finally** (hoặc cả hai)
- catch phải đứng **sau** try (nếu có)
- finally phải đứng **cuối cùng** (nếu có)
- Exception **cụ thể** phải đứng trước, **tổng quát** đứng sau

```java
// ✅ try-catch
try {
    // code
} catch (IOException e) {
    // handle
}

// ✅ try-finally
try {
    // code
} finally {
    // cleanup
}

// ✅ try-catch-finally
try {
    // code
} catch (IOException e) {
    // handle
} finally {
    // cleanup
}

// ❌ try alone - Compile error
try {
    // code
}

// ❌ finally before catch - Compile error
try {
    // code
} finally {
    // cleanup
} catch (IOException e) {  // Compile error
    // handle
}
```

**Thứ tự catch:**

```java
// ❌ Superclass trước subclass - Compile error
try {
    // code
} catch (Exception e) {          // Tổng quát
    // handle
} catch (IOException e) {        // Compile error: unreachable
    // handle
}

// ✅ Subclass trước superclass
try {
    // code
} catch (FileNotFoundException e) {  // Cụ thể nhất
    // handle
} catch (IOException e) {            // Cụ thể hơn
    // handle
} catch (Exception e) {              // Tổng quát nhất
    // handle
}
```

---

### 6.3. Multi-Catch

**Đặc điểm:**
- Biến exception trong multi-catch là **effectively final** (không thể gán lại)
- Các exception trong multi-catch **KHÔNG được** có quan hệ kế thừa cha-con
- Chỉ chấp nhận các exception không liên quan trực tiếp (sibling)

```java
// ✅ Multi-catch với sibling exceptions
try {
    // code
} catch (IOException | SQLException e) {  // e là effectively final
    System.out.println(e);
    // e = new IOException();  // ❌ Compile error: cannot assign
}

// ✅ Single catch - có thể reassign
try {
    // code
} catch (IOException e) {
    e = new IOException();  // ✅ OK
}

// ❌ Multi-catch với quan hệ cha-con - Compile error
try {
    // code
} catch (Exception | IOException e) {  // Compile error: redundant
    // IOException là subclass của Exception
}

// ✅ Multi-catch với nhiều sibling
try {
    // code
} catch (FileNotFoundException | SQLException | ArithmeticException e) {
    // OK - không có quan hệ kế thừa
}
```

---

### 6.4. Finally Block

**Đặc điểm:**
- Finally block **luôn** được thực thi (trừ System.exit() hoặc JVM crash)
- Chạy sau try/catch, trước khi return
- Nếu finally có return → ghi đè return trong try/catch

```java
// ⚠️ Finally luôn chạy
public static int test() {
    try {
        return 1;
    } finally {
        System.out.println("Finally");  // Chạy trước khi return
    }
}
// Output: Finally
// Return: 1

// ⚠️ Finally với return - ghi đè return của try
public static int test2() {
    try {
        return 1;
    } finally {
        return 2;  // Ghi đè return trong try
    }
}
// Return: 2

// ⚠️ Finally chạy ngay cả khi có exception
try {
    throw new IOException();
} catch (IOException e) {
    System.out.println("Catch");
} finally {
    System.out.println("Finally");  // Vẫn chạy
}
// Output: Catch → Finally

// ⚠️ Finally KHÔNG chạy nếu System.exit()
try {
    System.exit(0);
} finally {
    System.out.println("Finally");  // KHÔNG chạy
}
```

**Default Exception Handler:**
- Nếu exception không được catch đến main() → JVM gọi default exception handler
- Default handler: print stack trace và terminate chương trình

---

### 6.5. Try-With-Resources

**Đặc điểm:**
- Tự động đóng resource khi kết thúc try block
- Resource phải implement **AutoCloseable** hoặc **Closeable**
- Resources được đóng theo **thứ tự ngược** với khai báo
- **Không bắt buộc** có catch hoặc finally (khác try-catch thông thường)
- Biến resource là **implicitly final**

```java
// ✅ Try-with-resources cơ bản
try (FileReader fr = new FileReader("file.txt")) {
    // use fr
}  // fr.close() tự động được gọi

// ✅ Không cần catch hoặc finally
try (FileReader fr = new FileReader("file.txt")) {
    // code
}  // ✅ OK

// ✅ Multiple resources - đóng theo thứ tự ngược
try (FileReader fr = new FileReader("in.txt");
     FileWriter fw = new FileWriter("out.txt")) {
    // use fr and fw
}  // fw.close() trước, sau đó fr.close()

// ✅ Với catch và finally
try (FileReader fr = new FileReader("file.txt")) {
    // code
} catch (IOException e) {
    // handle
} finally {
    // cleanup
}
```

**Java 9+: Effectively Final Variables:**

```java
// ✅ Java 9+ - dùng biến effectively final
FileReader fr = new FileReader("file.txt");  // effectively final
try (fr) {  // Không cần khai báo lại
    // use fr
}

// ✅ Multiple effectively final resources
FileReader fr = new FileReader("in.txt");
FileWriter fw = new FileWriter("out.txt");
try (fr; fw) {
    // use fr and fw
}

// ❌ Biến không effectively final
FileReader fr = new FileReader("file.txt");
fr = new FileReader("other.txt");  // Reassigned
try (fr) {  // Compile error: not effectively final
}
```

**Suppressed Exceptions:**

Khi cả try block VÀ close() đều throw exception:
- Exception từ **try block** được ưu tiên (primary exception)
- Exception từ **close()** trở thành suppressed exception
- Lấy suppressed exceptions: `e.getSuppressed()`

```java
class MyResource implements AutoCloseable {
    public void doSomething() throws Exception {
        throw new Exception("Exception in try");
    }

    @Override
    public void close() throws Exception {
        throw new Exception("Exception in close");
    }
}

// Test
try (MyResource r = new MyResource()) {
    r.doSomething();  // throw "Exception in try"
} catch (Exception e) {
    System.out.println(e.getMessage());  // "Exception in try"

    Throwable[] suppressed = e.getSuppressed();
    System.out.println(suppressed[0].getMessage());  // "Exception in close"
}
```

**AutoCloseable vs Closeable:**

```java
// AutoCloseable - throws Exception
public interface AutoCloseable {
    void close() throws Exception;
}

// Closeable - throws IOException (subinterface của AutoCloseable)
public interface Closeable extends AutoCloseable {
    void close() throws IOException;
}

// ✅ Custom AutoCloseable
class MyResource implements AutoCloseable {
    @Override
    public void close() throws Exception {
        System.out.println("Closing");
    }
}

try (MyResource r = new MyResource()) {
    // use r
}  // close() tự động được gọi
```

---

### 6.6. Method Throws Declaration

**Quy tắc khai báo throws:**
- Checked exceptions **phải** khai báo throws (hoặc catch)
- Unchecked exceptions **không bắt buộc** khai báo
- Subclass override method **KHÔNG được** throws checked exception rộng hơn superclass

```java
// ✅ Khai báo checked exception
public void readFile() throws IOException {
    FileReader fr = new FileReader("file.txt");
}

// ✅ Khai báo multiple exceptions
public void process() throws IOException, SQLException {
    // code
}

// ✅ Unchecked exception - không bắt buộc khai báo
public void divide(int a, int b) {  // Không cần throws
    int result = a / b;  // Có thể throw ArithmeticException
}

// ✅ Có thể khai báo unchecked exception (optional)
public void divide(int a, int b) throws ArithmeticException {
    int result = a / b;
}
```

**Override Method Rules:**

```java
class Parent {
    public void method1() throws IOException {
    }

    public void method2() {
    }
}

class Child extends Parent {
    // ✅ Không throws - OK (hẹp hơn)
    @Override
    public void method1() {
    }

    // ✅ Throws subclass - OK
    @Override
    public void method1() throws FileNotFoundException {  // Subclass của IOException
    }

    // ❌ Throws superclass - Compile error
    @Override
    public void method1() throws Exception {  // Compile error: rộng hơn IOException
    }

    // ❌ Throws checked exception mới - Compile error
    @Override
    public void method2() throws IOException {  // Compile error: parent không throws
    }

    // ✅ Throws unchecked exception - OK (luôn được phép)
    @Override
    public void method2() throws RuntimeException {  // OK
    }
}
```

---

### 6.7. Custom Exceptions

```java
// ✅ Custom checked exception
class MyCheckedException extends Exception {
    public MyCheckedException(String message) {
        super(message);
    }
}

// ✅ Custom unchecked exception
class MyUncheckedException extends RuntimeException {
    public MyUncheckedException(String message) {
        super(message);
    }
}

// Usage
public void process() throws MyCheckedException {
    throw new MyCheckedException("Custom error");
}
```

---

### 6.8. Common Exceptions (Hay gặp trong thi)

**Runtime Exceptions (Unchecked):**

```java
// NullPointerException
String s = null;
s.length();  // NPE

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
arr[5] = 10;  // AIOOBE

// ClassCastException
Object obj = "String";
Integer num = (Integer) obj;  // CCE

// NumberFormatException (subclass của IllegalArgumentException)
Integer.parseInt("abc");  // NFE

// ArithmeticException
int x = 10 / 0;  // AE

// IllegalArgumentException
Thread t = new Thread();
t.setPriority(100);  // IAE (priority phải 1-10)

// UnsupportedOperationException
List<String> list = List.of("A", "B");
list.add("C");  // UOE
```

**Checked Exceptions:**

```java
// IOException
FileReader fr = new FileReader("file.txt");  // IOException

// FileNotFoundException (subclass của IOException)
FileInputStream fis = new FileInputStream("missing.txt");  // FNFE

// SQLException
Connection conn = DriverManager.getConnection(url);  // SQLException

// ClassNotFoundException
Class.forName("com.example.Missing");  // CNFE
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ⚠️ Unreachable catch block
try {
    System.out.println("OK");
} catch (IOException e) {  // Compile error: unreachable (try không throw IOException)
}

// ✅ OK với unchecked exception
try {
    System.out.println("OK");
} catch (RuntimeException e) {  // ✅ OK (unchecked)
}

// ⚠️ Multi-catch với duplicate
try {
    // code
} catch (IOException | IOException e) {  // Compile error: duplicate

// ⚠️ Exception variable scope
try {
    // code
} catch (IOException e) {
    // e visible here
}
// e NOT visible here

// ⚠️ Finally thay đổi return value
public static int test() {
    try {
        return 1;
    } finally {
        return 2;  // Ghi đè return 1
    }
}  // Returns 2

// ⚠️ Throw null
throw null;  // NullPointerException at runtime
```

---

### 6.9. AutoCloseable vs Closeable

**So sánh:**

| Đặc điểm | AutoCloseable | Closeable |
|----------|---------------|-----------|
| Package | `java.lang` | `java.io` |
| Mối quan hệ | Interface cha | Extends AutoCloseable |
| Exception throws | `throws Exception` | `throws IOException` |
| Idempotent | Không bắt buộc | **Bắt buộc** (gọi nhiều lần không ảnh hưởng) |
| Từ Java version | Java 7+ | Java 5+ |

**Interface Definition:**

```java
// AutoCloseable - cha
package java.lang;
public interface AutoCloseable {
    void close() throws Exception;  // Throws Exception (rộng)
}

// Closeable - con (subinterface)
package java.io;
public interface Closeable extends AutoCloseable {
    void close() throws IOException;  // Throws IOException (hẹp hơn)
}
```

**Sự khác biệt chính:**

1. **Exception thrown:**
   - `AutoCloseable.close()` throws `Exception` (checked exception rộng nhất)
   - `Closeable.close()` throws `IOException` (cụ thể hơn)

2. **Idempotency (tính bất biến):**
   - `Closeable` **bắt buộc** idempotent: gọi `close()` nhiều lần phải an toàn
   - `AutoCloseable` không bắt buộc idempotent: gọi lần 2 có thể throw exception

3. **Use case:**
   - `AutoCloseable`: Dùng cho tất cả resources (database connections, locks...)
   - `Closeable`: Dùng cho I/O resources (streams, readers, writers...)

**Ví dụ:**

```java
// ✅ AutoCloseable - có thể throw Exception
class DatabaseConnection implements AutoCloseable {
    @Override
    public void close() throws Exception {  // OK: throws Exception
        System.out.println("Closing DB connection");
        throw new Exception("DB close error");
    }
}

// ✅ Closeable - chỉ throw IOException, phải idempotent
class FileResource implements Closeable {
    private boolean closed = false;

    @Override
    public void close() throws IOException {  // Phải IOException (hoặc hẹp hơn)
        if (!closed) {  // Idempotent: check trước khi đóng
            System.out.println("Closing file");
            closed = true;
        }
        // Gọi lần 2, 3... không làm gì và không throw exception
    }
}

// ❌ Closeable không thể throw Exception rộng hơn
class WrongCloseable implements Closeable {
    @Override
    public void close() throws Exception {  // Compile error: incompatible exception
        // Cannot throw Exception, chỉ được IOException
    }
}
```

**Try-with-resources:**

```java
// ✅ Cả 2 đều dùng được với try-with-resources
try (DatabaseConnection db = new DatabaseConnection()) {
    // use db
} catch (Exception e) {  // Phải catch Exception (vì AutoCloseable throws Exception)
    e.printStackTrace();
}

try (FileResource file = new FileResource()) {
    // use file
} catch (IOException e) {  // Chỉ cần catch IOException
    e.printStackTrace();
}
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ⚠️ Closeable.close() idempotent
class MyCloseable implements Closeable {
    private boolean closed = false;

    @Override
    public void close() throws IOException {
        if (closed) {
            return;  // Đã đóng rồi, không làm gì
        }
        // Thực hiện đóng resource
        closed = true;
    }
}

MyCloseable resource = new MyCloseable();
resource.close();  // OK
resource.close();  // OK - không throw exception (idempotent)

// ⚠️ AutoCloseable.close() không bắt buộc idempotent
class MyAutoCloseable implements AutoCloseable {
    @Override
    public void close() throws Exception {
        System.out.println("Closing");
        throw new Exception("Already closed");  // Có thể throw mỗi lần gọi
    }
}

MyAutoCloseable auto = new MyAutoCloseable();
auto.close();  // Throws exception
auto.close();  // Throws exception lần nữa (không idempotent)

// ✅ Khi implement Closeable, override close() phải hẹp hơn hoặc bằng IOException
class GoodCloseable implements Closeable {
    @Override
    public void close() throws IOException { }  // ✅ OK

    @Override
    public void close() throws FileNotFoundException { }  // ✅ OK (hẹp hơn)

    @Override
    public void close() { }  // ✅ OK (không throws)

    @Override
    public void close() throws Exception { }  // ❌ Compile error (rộng hơn)
}

// ✅ Standard Java I/O classes implement Closeable
FileInputStream fis = new FileInputStream("file.txt");  // Closeable
BufferedReader br = new BufferedReader(new FileReader("file.txt"));  // Closeable

// ✅ JDBC classes implement AutoCloseable (không phải Closeable)
Connection conn = DriverManager.getConnection(url);  // AutoCloseable
Statement stmt = conn.createStatement();  // AutoCloseable
ResultSet rs = stmt.executeQuery(sql);  // AutoCloseable
```

**Tóm tắt:**
- **Closeable** = AutoCloseable + idempotent + chỉ throws IOException
- Dùng **Closeable** cho I/O operations
- Dùng **AutoCloseable** cho các resources khác (DB, locks, custom resources...)
- Cả 2 đều dùng được với try-with-resources

---

## 7. Concurrency

### 7.0. Thread Basics

**Creating Threads:**

Có 2 cách chính để tạo thread trong Java:

**1. Extend Thread class:**

```java
// ✅ Extend Thread
class MyThread extends Thread {
    @Override
    public void run() {
        System.out.println("Thread running: " + Thread.currentThread().getName());
    }
}

// Sử dụng
MyThread thread = new MyThread();
thread.start();  // Bắt đầu thread mới
```

**2. Implement Runnable interface:**

```java
// ✅ Implement Runnable (preferred)
class MyRunnable implements Runnable {
    @Override
    public void run() {
        System.out.println("Thread running: " + Thread.currentThread().getName());
    }
}

// Sử dụng
Thread thread = new Thread(new MyRunnable());
thread.start();

// ✅ Hoặc dùng lambda (Java 8+)
Thread thread2 = new Thread(() -> {
    System.out.println("Lambda thread");
});
thread2.start();
```

**⚠️ start() vs run():**

```java
Thread thread = new Thread(() -> System.out.println("Running"));

// ✅ start() - tạo thread mới
thread.start();  // Chạy trên thread mới

// ❌ run() - chạy trên thread hiện tại
thread.run();  // Chạy trên main thread (KHÔNG tạo thread mới!)
```

---

**Thread States (Lifecycle):**

Thread trong Java có 6 states (enum `Thread.State`):

```
NEW → RUNNABLE → (BLOCKED/WAITING/TIMED_WAITING) → RUNNABLE → TERMINATED
```

**1. NEW:**
- Thread được tạo nhưng chưa start()
- `Thread thread = new Thread(() -> {})`

**2. RUNNABLE:**
- Thread đang chạy hoặc sẵn sàng chạy (đợi CPU)
- Sau khi gọi `start()`

**3. BLOCKED:**
- Thread đang chờ monitor lock (synchronized)
- Ví dụ: đợi vào synchronized block

**4. WAITING:**
- Thread đang chờ vô thời hạn
- Gây ra bởi: `wait()`, `join()`, `LockSupport.park()`

**5. TIMED_WAITING:**
- Thread đang chờ có thời hạn
- Gây ra bởi: `sleep()`, `wait(timeout)`, `join(timeout)`

**6. TERMINATED:**
- Thread đã hoàn thành run()

```java
Thread thread = new Thread(() -> {
    try {
        Thread.sleep(1000);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
});

System.out.println(thread.getState());  // NEW

thread.start();
System.out.println(thread.getState());  // RUNNABLE

Thread.sleep(100);
System.out.println(thread.getState());  // TIMED_WAITING (do sleep)

thread.join();  // Đợi thread kết thúc
System.out.println(thread.getState());  // TERMINATED
```

---

**Thread Methods:**

**sleep(milliseconds):**
- Tạm dừng thread hiện tại trong khoảng thời gian
- **Không nhả lock** (nếu đang trong synchronized)
- Throws `InterruptedException`

```java
// ✅ sleep
try {
    Thread.sleep(1000);  // Sleep 1 giây
} catch (InterruptedException e) {
    e.printStackTrace();
}
```

**join():**
- Chờ thread kết thúc
- Có thể có timeout: `join(milliseconds)`

```java
// ✅ join - đợi thread kết thúc
Thread thread = new Thread(() -> {
    System.out.println("Working...");
    try { Thread.sleep(2000); } catch (InterruptedException e) {}
});

thread.start();
thread.join();  // Main thread đợi thread kết thúc
System.out.println("Thread finished");
```

**interrupt():**
- Gửi interrupt signal đến thread
- Thread cần check và handle interrupt

```java
// ✅ interrupt
Thread thread = new Thread(() -> {
    while (!Thread.currentThread().isInterrupted()) {
        System.out.println("Working...");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();  // Restore interrupt status
            break;
        }
    }
});

thread.start();
Thread.sleep(3000);
thread.interrupt();  // Interrupt thread
```

**isAlive():**
- Kiểm tra thread còn đang chạy

```java
Thread thread = new Thread(() -> {});
System.out.println(thread.isAlive());  // false (chưa start)

thread.start();
System.out.println(thread.isAlive());  // true (đang chạy)

thread.join();
System.out.println(thread.isAlive());  // false (đã kết thúc)
```

**setName() / getName():**
- Đặt/lấy tên thread

```java
Thread thread = new Thread(() -> {});
thread.setName("MyWorker");
System.out.println(thread.getName());  // "MyWorker"
```

**setPriority() / getPriority():**
- Đặt/lấy độ ưu tiên (1-10)
- MIN_PRIORITY = 1, NORM_PRIORITY = 5, MAX_PRIORITY = 10
- **Lưu ý:** Priority chỉ là gợi ý cho scheduler, không đảm bảo

```java
Thread thread = new Thread(() -> {});
thread.setPriority(Thread.MAX_PRIORITY);  // 10
System.out.println(thread.getPriority());  // 10
```

**setDaemon() / isDaemon():**
- Daemon thread: thread chạy nền, JVM thoát khi chỉ còn daemon threads
- Phải gọi **trước** `start()`

```java
Thread daemon = new Thread(() -> {
    while (true) {
        System.out.println("Daemon running");
        try { Thread.sleep(1000); } catch (InterruptedException e) {}
    }
});

daemon.setDaemon(true);  // Phải gọi trước start()
daemon.start();

// JVM sẽ thoát khi main thread kết thúc, không đợi daemon
```

---

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ Gọi start() nhiều lần
Thread thread = new Thread(() -> {});
thread.start();
thread.start();  // IllegalThreadStateException

// ❌ setDaemon() sau khi start()
Thread thread = new Thread(() -> {});
thread.start();
thread.setDaemon(true);  // IllegalThreadStateException

// ⚠️ sleep() trong synchronized - KHÔNG nhả lock
synchronized(lock) {
    Thread.sleep(1000);  // Vẫn giữ lock!
}

// ✅ wait() trong synchronized - nhả lock
synchronized(lock) {
    lock.wait(1000);  // Nhả lock
}

// ⚠️ join() có thể throw InterruptedException
Thread thread = new Thread(() -> {});
thread.start();
thread.join();  // Must handle InterruptedException

// ⚠️ Không thể restart thread đã TERMINATED
Thread thread = new Thread(() -> {});
thread.start();
thread.join();
thread.start();  // IllegalThreadStateException
```

---

### 7.1. Executor Framework

**Runnable vs Callable:**

**Runnable:** Interface đại diện cho task không trả về kết quả
- Method: `void run()` - không throws exception, không có return value
- Thường dùng cho các task không cần kết quả

**Callable<T>:** Interface đại diện cho task có trả về kết quả
- Method: `T call() throws Exception` - có thể throws exception và có return value
- Thường dùng khi cần kết quả từ task

```java
// ✅ Runnable - không return
Runnable task1 = () -> System.out.println("Running task");

// ✅ Callable - có return
Callable<String> task2 = () -> {
    Thread.sleep(1000);
    return "Task completed";
};
```

---

**Executor Framework Hierarchy:**

```
Executor (interface)
    └── ExecutorService (interface)
            └── ScheduledExecutorService (interface)
```

**Executor:** Functional interface cơ bản nhất
- Method: `void execute(Runnable command)`
- Chỉ thực thi task, không quản lý lifecycle

**ExecutorService:** Mở rộng của Executor, cung cấp quản lý vòng đời thread pool
- Methods chính:
  - `Future<?> submit(Runnable task)` - submit task và trả về Future
  - `<T> Future<T> submit(Callable<T> task)` - submit task với return value
  - `void execute(Runnable command)` - thực thi task (kế thừa từ Executor)
  - `void shutdown()` - ngừng nhận task mới, đợi task hiện tại hoàn thành
  - `List<Runnable> shutdownNow()` - dừng ngay, trả về danh sách task chưa chạy
  - `boolean awaitTermination(long timeout, TimeUnit unit)` - chờ tất cả task kết thúc
  - `<T> List<Future<T>> invokeAll(Collection<Callable<T>> tasks)` - thực thi tất cả tasks
  - `<T> T invokeAny(Collection<Callable<T>> tasks)` - trả về kết quả của task hoàn thành đầu tiên

```java
// ✅ Tạo ExecutorService
ExecutorService executor = Executors.newFixedThreadPool(5);

// ✅ Submit tasks
Future<String> future = executor.submit(() -> "Result");

// ✅ Shutdown
executor.shutdown();  // Không nhận task mới
executor.awaitTermination(1, TimeUnit.MINUTES);  // Đợi tối đa 1 phút
```

---

**Executors Factory Methods:**

Class `Executors` cung cấp các factory methods để tạo ExecutorService:

**1. newFixedThreadPool(int nThreads):**
- Tạo thread pool với số lượng thread cố định
- Các task chờ trong queue nếu tất cả threads đang busy
- Thread không bị hủy, tồn tại cho đến khi shutdown

```java
// ✅ Fixed thread pool
ExecutorService executor = Executors.newFixedThreadPool(5);
for (int i = 0; i < 100; i++) {
    executor.submit(() -> {
        System.out.println(Thread.currentThread().getName());
    });
}
// Chỉ có 5 threads xử lý 100 tasks
```

**2. newSingleThreadExecutor():**
- Tương đương với `newFixedThreadPool(1)`
- Chỉ có 1 thread duy nhất xử lý tasks tuần tự
- Đảm bảo thứ tự thực thi tasks theo FIFO

```java
// ✅ Single thread executor
ExecutorService executor = Executors.newSingleThreadExecutor();
executor.submit(() -> System.out.println("Task 1"));
executor.submit(() -> System.out.println("Task 2"));
// Task 2 chỉ chạy sau khi Task 1 hoàn thành
```

**3. newCachedThreadPool():**
- Không giới hạn số lượng threads
- Tạo thread mới nếu không có thread rảnh
- Tái sử dụng thread rảnh nếu có (timeout 60 giây)
- Thread không sử dụng quá 60 giây sẽ bị hủy
- **Rủi ro:** Có thể gây OutOfMemoryError nếu tạo quá nhiều threads
- **Phù hợp:** Các task ngắn, hoàn thành nhanh

```java
// ✅ Cached thread pool
ExecutorService executor = Executors.newCachedThreadPool();
for (int i = 0; i < 1000; i++) {
    executor.submit(() -> {
        // Short-lived task
        doQuickWork();
    });
}
// Có thể tạo rất nhiều threads nếu tasks đến nhanh
```

**4. newScheduledThreadPool(int corePoolSize):**
- Cho phép lên lịch thực thi task (delay hoặc định kỳ)
- Trả về `ScheduledExecutorService`

```java
// ✅ Scheduled thread pool
ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(3);

// Chạy sau 5 giây
scheduler.schedule(() -> System.out.println("Delayed task"), 5, TimeUnit.SECONDS);

// Chạy định kỳ mỗi 1 giây, bắt đầu sau 2 giây
scheduler.scheduleAtFixedRate(
    () -> System.out.println("Periodic task"),
    2,  // initial delay
    1,  // period
    TimeUnit.SECONDS
);

// Chạy định kỳ, delay 1 giây giữa lần kết thúc và lần bắt đầu tiếp theo
scheduler.scheduleWithFixedDelay(
    () -> System.out.println("Fixed delay task"),
    2,  // initial delay
    1,  // delay between executions
    TimeUnit.SECONDS
);
```

---

**Submitting Tasks:**

**1. execute(Runnable):**
- Không trả về kết quả
- Không biết task thành công hay thất bại
- Exception xảy ra trong worker thread, không lan ra thread gọi

```java
// ✅ execute - fire and forget
executor.execute(() -> {
    System.out.println("Task running");
    // Exception ở đây chỉ ảnh hưởng worker thread
});
```

**2. submit(Runnable):**
- Trả về `Future<?>`
- `Future.get()` trả về `null` nếu thành công
- Exception được wrap trong Future, chỉ throw khi gọi `Future.get()`

```java
// ✅ submit Runnable
Future<?> future = executor.submit(() -> {
    System.out.println("Task running");
    if (someCondition) {
        throw new RuntimeException("Error!");
    }
});

try {
    future.get();  // null nếu thành công, throw Exception nếu có lỗi
} catch (ExecutionException e) {
    Throwable cause = e.getCause();  // Lấy exception gốc
}
```

**3. submit(Callable<T>):**
- Trả về `Future<T>`
- `Future.get()` trả về giá trị của `call()`
- Exception được wrap trong Future

```java
// ✅ submit Callable
Future<Integer> future = executor.submit(() -> {
    Thread.sleep(1000);
    return 42;
});

try {
    Integer result = future.get();  // 42
    System.out.println(result);
} catch (ExecutionException e) {
    // Handle exception from call()
}
```

---

**Future<T> Interface:**

Đại diện cho kết quả của một async computation.

**Methods:**

```java
Future<String> future = executor.submit(() -> {
    Thread.sleep(2000);
    return "Done";
});

// ✅ get() - block cho đến khi task hoàn thành
String result = future.get();  // Đợi vô hạn

// ✅ get(timeout, unit) - block với timeout
try {
    String result = future.get(1, TimeUnit.SECONDS);
} catch (TimeoutException e) {
    System.out.println("Task timed out");
}

// ✅ cancel(boolean mayInterruptIfRunning)
future.cancel(true);   // Ngắt thread nếu đang chạy
future.cancel(false);  // Chỉ cancel nếu chưa chạy

// ✅ isCancelled() - kiểm tra đã bị cancel
boolean cancelled = future.isCancelled();

// ✅ isDone() - kiểm tra đã hoàn thành
// true nếu: hoàn thành bình thường, bị cancel, hoặc có exception
boolean done = future.isDone();
```

**⚠️ Lưu ý:**
```java
// ❌ Calling get() on infinite task - block forever
Future<Void> future = executor.submit(() -> {
    while (true) {
        // Infinite loop
    }
});
future.get();  // Block vô hạn!

// ✅ Sử dụng timeout
try {
    future.get(5, TimeUnit.SECONDS);
} catch (TimeoutException e) {
    future.cancel(true);  // Cancel task
}
```

---

**invokeAll() và invokeAny():**

```java
// ✅ invokeAll - thực thi tất cả tasks, đợi tất cả hoàn thành
List<Callable<String>> tasks = List.of(
    () -> "Task 1",
    () -> "Task 2",
    () -> "Task 3"
);

List<Future<String>> futures = executor.invokeAll(tasks);
for (Future<String> future : futures) {
    System.out.println(future.get());  // Đã hoàn thành rồi
}

// ✅ invokeAny - trả về kết quả của task hoàn thành đầu tiên
String result = executor.invokeAny(tasks);  // "Task 1" hoặc "Task 2" hoặc "Task 3"
// Các task khác bị cancel
```

---

**Exception Handling:**

```java
// ❌ execute() - exception không được catch
executor.execute(() -> {
    throw new RuntimeException("Error in execute");
    // Exception printed to console, không thể catch
});

// ✅ submit() - exception wrapped in Future
Future<?> future = executor.submit(() -> {
    throw new RuntimeException("Error in submit");
});

try {
    future.get();
} catch (ExecutionException e) {
    System.out.println("Caught: " + e.getCause().getMessage());
}
```

---

**Shutdown ExecutorService:**

```java
// ✅ Graceful shutdown
executor.shutdown();  // Không nhận task mới
// Các task đang chạy và đang chờ sẽ tiếp tục

// Đợi tất cả tasks hoàn thành
if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
    // Timeout - force shutdown
    executor.shutdownNow();
}

// ❌ Force shutdown
List<Runnable> pendingTasks = executor.shutdownNow();
// Ngắt tất cả threads, trả về danh sách tasks chưa chạy
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ Quên shutdown - program không thoát
ExecutorService executor = Executors.newFixedThreadPool(5);
executor.submit(() -> System.out.println("Task"));
// Threads vẫn chạy, JVM không thoát!

// ✅ Luôn shutdown
executor.shutdown();

// ❌ Submit task sau khi shutdown
executor.shutdown();
executor.submit(() -> System.out.println("Task"));  // RejectedExecutionException

// ⚠️ awaitTermination không shutdown
executor.awaitTermination(1, TimeUnit.MINUTES);  // Chỉ đợi, không shutdown!
// Phải gọi shutdown() trước

// ✅ Đúng cách
executor.shutdown();
executor.awaitTermination(1, TimeUnit.MINUTES);

// ⚠️ Callable vs Runnable với submit
Future<String> f1 = executor.submit(() -> "Result");  // Callable
Future<?> f2 = executor.submit(() -> System.out.println("Task"));  // Runnable

f1.get();  // "Result"
f2.get();  // null
```

---

### 7.2. Synchronization

**synchronized Keyword:**

Từ khóa `synchronized` được dùng để đảm bảo chỉ một thread được truy cập critical section (đoạn mã quan trọng) tại một thời điểm, tránh race condition.

**synchronized Block:**

```java
// ✅ synchronized với object
private Object lock = new Object();

public void method() {
    synchronized (lock) {
        // Critical section
        // Chỉ 1 thread có thể vào đây tại một thời điểm
    }
}

// ✅ synchronized với this
public void method() {
    synchronized (this) {
        // Lock trên instance hiện tại
    }
}

// ✅ synchronized với class
public void method() {
    synchronized (MyClass.class) {
        // Lock trên class object
        // Tất cả instances chia sẻ chung lock này
    }
}
```

**synchronized Method:**

```java
// ✅ synchronized instance method
// Tương đương: synchronized(this)
public synchronized void instanceMethod() {
    // Chỉ 1 thread trên cùng 1 instance tại một thời điểm
    // Các instance khác vẫn có thể chạy song song
}

// ✅ synchronized static method
// Tương đương: synchronized(MyClass.class)
public static synchronized void staticMethod() {
    // Chỉ 1 thread trên tất cả instances tại một thời điểm
    // Lock được chia sẻ giữa tất cả instances
}
```

**⚠️ Lưu ý về Locks:**

```java
class Counter {
    private int count = 0;

    // ✅ Instance method - lock trên this
    public synchronized void increment() {
        count++;
    }
}

Counter c1 = new Counter();
Counter c2 = new Counter();

// c1 và c2 có locks riêng biệt
// 2 threads có thể chạy song song trên c1 và c2
Thread t1 = new Thread(() -> c1.increment());
Thread t2 = new Thread(() -> c2.increment());  // Không bị block bởi t1

// ❌ Không nên lock trên object có thể thay đổi
private String lock = "lock";  // String pooling!
synchronized(lock) { }  // Nguy hiểm!

// ✅ Nên dùng final Object
private final Object lock = new Object();
synchronized(lock) { }
```

**Monitor Lock:**

Mỗi object trong Java có một **monitor lock** (intrinsic lock). Khi thread acquire lock, các threads khác phải chờ trong **wait set** (hàng đợi).

```java
class BankAccount {
    private int balance = 100;
    private final Object lock = new Object();

    public void withdraw(int amount) {
        synchronized(lock) {  // Acquire monitor lock
            if (balance >= amount) {
                balance -= amount;
            }
        }  // Release monitor lock
    }

    public void deposit(int amount) {
        synchronized(lock) {  // Cùng lock với withdraw
            balance += amount;
        }
    }
}
```

---

**wait(), notify(), notifyAll():**

Các methods này thuộc class `Object`, dùng để thread communication trong synchronized block.

**wait():**
- Thread nhả lock và vào **WAITING** state
- Thread chờ cho đến khi được notify
- **Phải gọi trong synchronized block**

**notify():**
- Đánh thức **1 thread bất kỳ** đang wait trên cùng lock
- Thread được đánh thức sẽ cạnh tranh lại để acquire lock

**notifyAll():**
- Đánh thức **TẤT CẢ threads** đang wait trên cùng lock
- Tất cả threads sẽ cạnh tranh để acquire lock

```java
class ProducerConsumer {
    private final List<Integer> queue = new ArrayList<>();
    private final int MAX = 5;
    private final Object lock = new Object();

    public void produce(int value) throws InterruptedException {
        synchronized(lock) {
            // Đợi nếu queue đầy
            while (queue.size() == MAX) {
                lock.wait();  // Nhả lock và đợi
            }

            queue.add(value);
            System.out.println("Produced: " + value);

            lock.notifyAll();  // Đánh thức consumer
        }
    }

    public int consume() throws InterruptedException {
        synchronized(lock) {
            // Đợi nếu queue rỗng
            while (queue.isEmpty()) {
                lock.wait();  // Nhả lock và đợi
            }

            int value = queue.remove(0);
            System.out.println("Consumed: " + value);

            lock.notifyAll();  // Đánh thức producer
            return value;
        }
    }
}
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ wait() ngoài synchronized block
Object lock = new Object();
lock.wait();  // IllegalMonitorStateException

// ✅ Phải gọi trong synchronized
synchronized(lock) {
    lock.wait();  // OK
}

// ❌ Dùng if thay vì while
synchronized(lock) {
    if (condition) {
        lock.wait();  // Có thể bị spurious wakeup!
    }
}

// ✅ Luôn dùng while
synchronized(lock) {
    while (condition) {
        lock.wait();  // Re-check sau khi wake up
    }
}

// ⚠️ notify() vs notifyAll()
// notify() - chỉ đánh thức 1 thread (không biết thread nào)
// notifyAll() - đánh thức tất cả (an toàn hơn)

synchronized(lock) {
    lock.notify();     // Có thể gây deadlock nếu đánh thức sai thread
    lock.notifyAll();  // An toàn hơn nhưng overhead cao hơn
}
```

---

**ReentrantLock:**

`ReentrantLock` là alternative của `synchronized`, cung cấp nhiều tính năng hơn.

**Ưu điểm so với synchronized:**
- Có thể **try lock** mà không block
- Có thể **interrupt** thread đang đợi lock
- Có thể **timeout** khi chờ lock
- Hỗ trợ **fair locking** (FIFO)
- Hỗ trợ nhiều **Condition** objects

**Nhược điểm:**
- Phải **unlock thủ công** (dễ quên)
- Nên dùng trong try-finally để đảm bảo unlock

```java
import java.util.concurrent.locks.ReentrantLock;

class Counter {
    private int count = 0;
    private final ReentrantLock lock = new ReentrantLock();

    // ✅ Luôn dùng try-finally
    public void increment() {
        lock.lock();
        try {
            count++;
        } finally {
            lock.unlock();  // Đảm bảo luôn unlock
        }
    }

    // ✅ tryLock - không block
    public boolean tryIncrement() {
        if (lock.tryLock()) {  // Acquire ngay, không chờ
            try {
                count++;
                return true;
            } finally {
                lock.unlock();
            }
        }
        return false;  // Không acquire được lock
    }

    // ✅ tryLock với timeout
    public boolean tryIncrementWithTimeout() throws InterruptedException {
        if (lock.tryLock(1, TimeUnit.SECONDS)) {  // Chờ tối đa 1 giây
            try {
                count++;
                return true;
            } finally {
                lock.unlock();
            }
        }
        return false;
    }

    // ✅ lockInterruptibly - có thể bị interrupt
    public void incrementInterruptibly() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            count++;
        } finally {
            lock.unlock();
        }
    }
}
```

**Fair vs Unfair Lock:**

```java
// ✅ Unfair lock (default) - hiệu suất cao hơn
ReentrantLock unfairLock = new ReentrantLock();

// ✅ Fair lock - FIFO, tránh starvation
ReentrantLock fairLock = new ReentrantLock(true);
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
ReentrantLock lock = new ReentrantLock();

// ❌ Quên unlock - deadlock!
lock.lock();
count++;
// Quên unlock!

// ✅ Luôn dùng try-finally
lock.lock();
try {
    count++;
} finally {
    lock.unlock();
}

// ❌ unlock mà không lock
lock.unlock();  // IllegalMonitorStateException

// ❌ unlock nhiều hơn lock
lock.lock();
try {
    count++;
} finally {
    lock.unlock();
    lock.unlock();  // IllegalMonitorStateException
}
```

---

**Condition:**

`Condition` là alternative của `wait()/notify()`, cung cấp nhiều wait queues cho cùng 1 lock.

```java
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

class BoundedBuffer {
    private final List<Integer> buffer = new ArrayList<>();
    private final int MAX = 5;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notFull = lock.newCondition();   // Queue cho producer
    private final Condition notEmpty = lock.newCondition();  // Queue cho consumer

    public void produce(int value) throws InterruptedException {
        lock.lock();
        try {
            // Đợi nếu buffer đầy
            while (buffer.size() == MAX) {
                notFull.await();  // Tương đương wait()
            }

            buffer.add(value);
            System.out.println("Produced: " + value);

            notEmpty.signal();  // Đánh thức consumer (tương đương notify())
        } finally {
            lock.unlock();
        }
    }

    public int consume() throws InterruptedException {
        lock.lock();
        try {
            // Đợi nếu buffer rỗng
            while (buffer.isEmpty()) {
                notEmpty.await();
            }

            int value = buffer.remove(0);
            System.out.println("Consumed: " + value);

            notFull.signal();  // Đánh thức producer
            return value;
        } finally {
            lock.unlock();
        }
    }
}
```

**Condition Methods:**

| wait/notify | Condition | Mô tả |
|-------------|-----------|-------|
| `wait()` | `await()` | Nhả lock và đợi |
| `wait(timeout)` | `await(timeout, unit)` | Đợi với timeout |
| `notify()` | `signal()` | Đánh thức 1 thread |
| `notifyAll()` | `signalAll()` | Đánh thức tất cả threads |

**⚠️ Lưu ý:**
```java
// ❌ await() ngoài lock
Condition condition = lock.newCondition();
condition.await();  // IllegalMonitorStateException

// ✅ Phải gọi sau khi lock
lock.lock();
try {
    condition.await();  // OK
} finally {
    lock.unlock();
}
```

---

**volatile Keyword:**

`volatile` đảm bảo **visibility** - mọi thread đều thấy giá trị mới nhất của biến.

**Khi dùng volatile:**
- Đọc/ghi biến đơn giản (không có compound operations)
- Không cần atomic operations
- Biến được ghi bởi 1 thread, đọc bởi nhiều threads

**volatile không đảm bảo atomicity:**

```java
class VolatileExample {
    private volatile boolean flag = false;
    private volatile int counter = 0;

    // ✅ OK - đọc/ghi đơn giản
    public void setFlag() {
        flag = true;  // Atomic
    }

    public boolean getFlag() {
        return flag;  // Luôn đọc giá trị mới nhất
    }

    // ❌ NOT thread-safe - compound operation
    public void increment() {
        counter++;  // Read-Modify-Write - KHÔNG atomic!
    }
}
```

**volatile vs synchronized:**

```java
// ✅ volatile - chỉ đảm bảo visibility
private volatile boolean running = true;

public void stop() {
    running = false;  // Thread khác sẽ thấy ngay
}

public void run() {
    while (running) {  // Luôn đọc giá trị mới nhất
        // ...
    }
}

// ✅ synchronized - đảm bảo cả atomicity và visibility
private int count = 0;

public synchronized void increment() {
    count++;  // Atomic và visible
}
```

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ❌ volatile không đảm bảo atomicity
private volatile int count = 0;

public void increment() {
    count++;  // KHÔNG thread-safe! (3 operations: read, increment, write)
}

// ✅ Cần synchronized hoặc AtomicInteger
private int count = 0;

public synchronized void increment() {
    count++;  // Thread-safe
}

// Hoặc
private AtomicInteger count = new AtomicInteger(0);

public void increment() {
    count.incrementAndGet();  // Thread-safe
}

// ✅ volatile phù hợp cho flag
private volatile boolean stopped = false;

public void shutdown() {
    stopped = true;
}

public void run() {
    while (!stopped) {
        // Do work
    }
}
```

---

### 7.3. Atomic Variables

Package `java.util.concurrent.atomic` cung cấp các class hỗ trợ atomic operations mà không cần synchronized.

**Các class chính:**
- `AtomicInteger` - atomic int operations
- `AtomicLong` - atomic long operations
- `AtomicBoolean` - atomic boolean operations
- `AtomicReference<V>` - atomic object reference operations

**Ưu điểm:**
- Thread-safe mà không cần synchronized
- Hiệu suất cao hơn synchronized (lock-free)
- Hỗ trợ compare-and-swap (CAS) operations

---

**AtomicInteger:**

```java
import java.util.concurrent.atomic.AtomicInteger;

AtomicInteger counter = new AtomicInteger(0);

// ✅ get() - lấy giá trị
int value = counter.get();  // 0

// ✅ set() - đặt giá trị
counter.set(10);

// ✅ incrementAndGet() - tăng và trả về giá trị mới
int newValue = counter.incrementAndGet();  // 11

// ✅ getAndIncrement() - trả về giá trị cũ và tăng
int oldValue = counter.getAndIncrement();  // 11, counter = 12

// ✅ decrementAndGet() - giảm và trả về giá trị mới
int decreased = counter.decrementAndGet();  // 11

// ✅ getAndDecrement() - trả về giá trị cũ và giảm
int old = counter.getAndDecrement();  // 11, counter = 10

// ✅ addAndGet(delta) - cộng và trả về giá trị mới
int result = counter.addAndGet(5);  // 15

// ✅ getAndAdd(delta) - trả về giá trị cũ và cộng
int prev = counter.getAndAdd(5);  // 15, counter = 20

// ✅ compareAndSet(expect, update) - CAS operation
boolean success = counter.compareAndSet(20, 100);  // true nếu counter = 20
// Nếu true: counter = 100
// Nếu false: counter không đổi

// ✅ getAndSet(newValue) - đặt giá trị mới và trả về giá trị cũ
int previous = counter.getAndSet(50);  // 100, counter = 50
```

**Thread-safe Counter Example:**

```java
// ❌ Không thread-safe
class UnsafeCounter {
    private int count = 0;

    public void increment() {
        count++;  // NOT atomic!
    }

    public int getCount() {
        return count;
    }
}

// ✅ Thread-safe với AtomicInteger
class SafeCounter {
    private AtomicInteger count = new AtomicInteger(0);

    public void increment() {
        count.incrementAndGet();  // Atomic!
    }

    public int getCount() {
        return count.get();
    }
}
```

---

**AtomicLong:**

Tương tự `AtomicInteger`, dùng cho `long`:

```java
import java.util.concurrent.atomic.AtomicLong;

AtomicLong counter = new AtomicLong(0L);

counter.incrementAndGet();     // Tăng
counter.getAndIncrement();     // Tăng
counter.decrementAndGet();     // Giảm
counter.addAndGet(100L);       // Cộng
counter.compareAndSet(100L, 200L);  // CAS
```

---

**AtomicBoolean:**

```java
import java.util.concurrent.atomic.AtomicBoolean;

AtomicBoolean flag = new AtomicBoolean(false);

// ✅ get() và set()
boolean value = flag.get();  // false
flag.set(true);

// ✅ getAndSet() - atomic swap
boolean oldValue = flag.getAndSet(false);  // true, flag = false

// ✅ compareAndSet(expect, update)
boolean success = flag.compareAndSet(false, true);  // true nếu flag = false
```

**Use case - One-time initialization:**

```java
class Initializer {
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    public void initialize() {
        // Chỉ thread đầu tiên được initialize
        if (initialized.compareAndSet(false, true)) {
            // Perform initialization
            System.out.println("Initializing...");
        } else {
            System.out.println("Already initialized");
        }
    }
}
```

---

**AtomicReference<V>:**

Atomic operations trên object reference:

```java
import java.util.concurrent.atomic.AtomicReference;

AtomicReference<String> ref = new AtomicReference<>("Initial");

// ✅ get() và set()
String value = ref.get();  // "Initial"
ref.set("Updated");

// ✅ getAndSet()
String old = ref.getAndSet("New");  // "Updated", ref = "New"

// ✅ compareAndSet(expect, update)
boolean success = ref.compareAndSet("New", "Final");  // true
// Nếu ref = "New" thì ref = "Final"

// ✅ Use case - immutable updates
class Person {
    private final String name;
    private final int age;

    Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    Person withAge(int newAge) {
        return new Person(this.name, newAge);
    }
}

AtomicReference<Person> personRef = new AtomicReference<>(new Person("John", 30));

// Atomic update
Person current, updated;
do {
    current = personRef.get();
    updated = current.withAge(31);
} while (!personRef.compareAndSet(current, updated));
```

---

**compareAndSet() - Compare-And-Swap:**

CAS là operation cơ bản của atomic classes:

```java
AtomicInteger counter = new AtomicInteger(10);

// ✅ compareAndSet(expectedValue, newValue)
boolean result = counter.compareAndSet(10, 20);
// Nếu counter = 10 (expected):
//   - Set counter = 20
//   - Return true
// Nếu counter != 10:
//   - Không thay đổi
//   - Return false

System.out.println(result);       // true
System.out.println(counter.get()); // 20

// ❌ CAS thất bại
boolean fail = counter.compareAndSet(10, 30);  // false (counter = 20, not 10)
System.out.println(counter.get());  // 20 (không đổi)
```

**CAS Loop Pattern:**

```java
AtomicInteger counter = new AtomicInteger(0);

// ✅ Atomic increment với CAS
public void increment() {
    int current;
    int next;
    do {
        current = counter.get();
        next = current + 1;
    } while (!counter.compareAndSet(current, next));
}

// Tương đương với counter.incrementAndGet()
```

---

**⚠️ Các trường hợp hay gặp trong thi:**

```java
// ⚠️ get() + set() KHÔNG atomic
AtomicInteger counter = new AtomicInteger(0);

// ❌ Không thread-safe!
int value = counter.get();
counter.set(value + 1);  // Race condition!

// ✅ Dùng incrementAndGet()
counter.incrementAndGet();  // Thread-safe

// ⚠️ Multiple operations không atomic
AtomicInteger a = new AtomicInteger(0);
AtomicInteger b = new AtomicInteger(0);

// ❌ Không atomic khi update cả 2
a.incrementAndGet();
b.incrementAndGet();
// Thread khác có thể thấy a tăng nhưng b chưa

// ✅ Cần synchronized nếu cần atomic cho nhiều operations
synchronized(lock) {
    a.incrementAndGet();
    b.incrementAndGet();
}

// ⚠️ AtomicReference với mutable objects
class MutablePerson {
    private String name;
    public void setName(String name) { this.name = name; }
}

AtomicReference<MutablePerson> ref = new AtomicReference<>(new MutablePerson());

// ❌ Reference là atomic nhưng mutations KHÔNG!
ref.get().setName("John");  // NOT thread-safe!

// ✅ Nên dùng với immutable objects
```

---

### 7.4. Concurrent Collections

Package `java.util.concurrent` cung cấp các collection implementations thread-safe với hiệu suất cao.

**Các interface và implementations:**

**List:**
- `CopyOnWriteArrayList` - thread-safe ArrayList

**Set:**
- `CopyOnWriteArraySet` - thread-safe Set
- `ConcurrentSkipListSet` - thread-safe sorted Set

**Map:**
- `ConcurrentHashMap` - thread-safe HashMap
- `ConcurrentSkipListMap` - thread-safe sorted Map

**Queue:**
- `ConcurrentLinkedQueue` - thread-safe unbounded queue
- `LinkedBlockingQueue` - thread-safe bounded/unbounded blocking queue
- `ArrayBlockingQueue` - thread-safe bounded blocking queue
- `PriorityBlockingQueue` - thread-safe priority queue

---

**CopyOnWriteArrayList:**

Thread-safe ArrayList, copy toàn bộ array khi modify (write).

**Đặc điểm:**
- **Thread-safe** mà không cần external synchronization
- **Iterators** không throw `ConcurrentModificationException`
- **Snapshot iteration** - iterator thấy trạng thái tại thời điểm tạo
- **Chậm** khi write (do copy), **nhanh** khi read
- **Phù hợp:** Nhiều read, ít write

```java
import java.util.concurrent.CopyOnWriteArrayList;

CopyOnWriteArrayList<String> list = new CopyOnWriteArrayList<>();

// ✅ Thread-safe add
list.add("A");
list.add("B");
list.add("C");

// ✅ Iterator không throw ConcurrentModificationException
Iterator<String> it = list.iterator();
list.add("D");  // Modify during iteration
while (it.hasNext()) {
    System.out.println(it.next());  // A, B, C (không thấy "D")
}

// ✅ Multiple threads
ExecutorService executor = Executors.newFixedThreadPool(10);
for (int i = 0; i < 100; i++) {
    executor.submit(() -> list.add("Item"));
}
// Thread-safe, không cần synchronized
```

**⚠️ Lưu ý:**

```java
// ⚠️ Iterator là snapshot
CopyOnWriteArrayList<String> list = new CopyOnWriteArrayList<>(List.of("A", "B"));
Iterator<String> it = list.iterator();

list.add("C");  // Modify
list.remove("A");  // Modify

while (it.hasNext()) {
    System.out.println(it.next());  // A, B (snapshot tại thời điểm tạo iterator)
}

System.out.println(list);  // [B, C] (trạng thái hiện tại)

// ❌ Iterator.remove() không hỗ trợ
Iterator<String> it2 = list.iterator();
it2.next();
it2.remove();  // UnsupportedOperationException
```

---

**ConcurrentHashMap:**

Thread-safe HashMap với hiệu suất cao, không block toàn bộ map.

**Đặc điểm:**
- **Thread-safe** mà không cần external synchronization
- **Lock striping** - chỉ lock một phần map
- **Không cho phép** null key hoặc null value
- **Atomic operations**: `putIfAbsent()`, `remove()`, `replace()`
- **Weakly consistent iterators** - không throw `ConcurrentModificationException`

```java
import java.util.concurrent.ConcurrentHashMap;

ConcurrentHashMap<String, Integer> map = new ConcurrentHashMap<>();

// ✅ Thread-safe put/get
map.put("A", 1);
map.put("B", 2);

Integer value = map.get("A");  // 1

// ✅ putIfAbsent - atomic
Integer prev = map.putIfAbsent("C", 3);  // null (key chưa tồn tại)
Integer prev2 = map.putIfAbsent("C", 4);  // 3 (key đã tồn tại, không update)

// ✅ remove(key, value) - atomic
boolean removed = map.remove("A", 1);  // true (xóa nếu key = "A" và value = 1)
boolean notRemoved = map.remove("B", 99);  // false (value không khớp)

// ✅ replace(key, oldValue, newValue) - atomic
boolean replaced = map.replace("B", 2, 20);  // true
boolean notReplaced = map.replace("B", 2, 30);  // false (oldValue không khớp)

// ✅ replace(key, value) - atomic (không cần oldValue)
Integer old = map.replace("B", 200);  // 20, map = {B=200, C=3}

// ✅ computeIfAbsent
map.computeIfAbsent("D", k -> k.length());  // D=1 (tính value từ key)

// ✅ computeIfPresent
map.computeIfPresent("D", (k, v) -> v * 2);  // D=2 (update value)

// ✅ compute
map.compute("E", (k, v) -> (v == null) ? 1 : v + 1);  // E=1

// ✅ merge
map.merge("E", 10, (oldVal, newVal) -> oldVal + newVal);  // E=11
```

**⚠️ Lưu ý:**

```java
// ❌ Không cho phép null key hoặc null value
ConcurrentHashMap<String, Integer> map = new ConcurrentHashMap<>();
map.put(null, 1);      // NullPointerException
map.put("A", null);    // NullPointerException

// ✅ HashMap cho phép null
HashMap<String, Integer> hashMap = new HashMap<>();
hashMap.put(null, 1);   // OK
hashMap.put("A", null); // OK

// ⚠️ Iterator là weakly consistent
ConcurrentHashMap<String, Integer> map = new ConcurrentHashMap<>(Map.of("A", 1, "B", 2));
Iterator<String> it = map.keySet().iterator();

map.put("C", 3);  // Modify during iteration

while (it.hasNext()) {
    System.out.println(it.next());  // Có thể hoặc không thấy "C"
}
// Không throw ConcurrentModificationException

// ⚠️ size() có thể không chính xác khi concurrent updates
// Chỉ là estimate
int size = map.size();  // Approximate
```

---

**BlockingQueue:**

Queue hỗ trợ blocking operations - chờ khi queue rỗng (take) hoặc đầy (put).

**Implementations:**
- `LinkedBlockingQueue` - unbounded/bounded FIFO queue
- `ArrayBlockingQueue` - bounded FIFO queue (fixed size)
- `PriorityBlockingQueue` - unbounded priority queue

**Methods:**

| Operation | Throws Exception | Returns Special | Blocks | Times Out |
|-----------|-----------------|-----------------|---------|-----------|
| Insert | `add(e)` | `offer(e)` | `put(e)` | `offer(e, time, unit)` |
| Remove | `remove()` | `poll()` | `take()` | `poll(time, unit)` |
| Examine | `element()` | `peek()` | N/A | N/A |

```java
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;

// ✅ LinkedBlockingQueue - unbounded
LinkedBlockingQueue<Integer> unbounded = new LinkedBlockingQueue<>();

unbounded.put(1);   // Block nếu đầy (nhưng unbounded nên không bao giờ đầy)
Integer value = unbounded.take();  // Block nếu rỗng

// ✅ ArrayBlockingQueue - bounded (capacity cố định)
ArrayBlockingQueue<Integer> bounded = new ArrayBlockingQueue<>(5);  // Max 5 elements

bounded.put(1);  // OK
bounded.put(2);  // OK
// ... bounded.put(5);  // OK
// bounded.put(6);  // BLOCK (queue đầy)

// ✅ offer() với timeout
boolean added = bounded.offer(6, 1, TimeUnit.SECONDS);  // Chờ 1 giây
// false nếu vẫn đầy sau 1 giây

// ✅ poll() với timeout
Integer val = bounded.poll(1, TimeUnit.SECONDS);  // Chờ 1 giây nếu rỗng
// null nếu vẫn rỗng sau 1 giây
```

**Producer-Consumer với BlockingQueue:**

```java
BlockingQueue<Integer> queue = new LinkedBlockingQueue<>(10);

// Producer
Runnable producer = () -> {
    try {
        for (int i = 0; i < 100; i++) {
            queue.put(i);  // Block nếu queue đầy
            System.out.println("Produced: " + i);
        }
    } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
    }
};

// Consumer
Runnable consumer = () -> {
    try {
        while (true) {
            Integer item = queue.take();  // Block nếu queue rỗng
            System.out.println("Consumed: " + item);
        }
    } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
    }
};

new Thread(producer).start();
new Thread(consumer).start();
```

---

**ConcurrentLinkedQueue:**

Thread-safe unbounded FIFO queue (non-blocking).

```java
import java.util.concurrent.ConcurrentLinkedQueue;

ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<>();

// ✅ Thread-safe operations
queue.offer("A");   // Add
queue.offer("B");

String head = queue.peek();  // "A" (không remove)
String removed = queue.poll();  // "A" (remove và return)

// ✅ Không block - trả về null nếu rỗng
String empty = queue.poll();  // null (queue rỗng)
```

---

**⚠️ So sánh Concurrent Collections:**

```java
// CopyOnWriteArrayList vs Collections.synchronizedList
List<String> syncList = Collections.synchronizedList(new ArrayList<>());
CopyOnWriteArrayList<String> cowList = new CopyOnWriteArrayList<>();

// syncList: Lock toàn bộ list khi read/write
// cowList: Copy array khi write, không lock khi read

// ❌ Collections.synchronizedList - iterator cần external sync
synchronized(syncList) {
    Iterator<String> it = syncList.iterator();
    while (it.hasNext()) {
        System.out.println(it.next());
    }
}

// ✅ CopyOnWriteArrayList - iterator không cần sync
Iterator<String> it = cowList.iterator();
while (it.hasNext()) {
    System.out.println(it.next());  // Thread-safe
}

// ConcurrentHashMap vs Collections.synchronizedMap
Map<String, Integer> syncMap = Collections.synchronizedMap(new HashMap<>());
ConcurrentHashMap<String, Integer> concMap = new ConcurrentHashMap<>();

// syncMap: Lock toàn bộ map
// concMap: Lock striping (chỉ lock một phần)

// BlockingQueue vs ConcurrentLinkedQueue
BlockingQueue<String> blocking = new LinkedBlockingQueue<>();
ConcurrentLinkedQueue<String> nonBlocking = new ConcurrentLinkedQueue<>();

blocking.take();     // BLOCK nếu rỗng
nonBlocking.poll();  // Return null nếu rỗng (không block)
```
---