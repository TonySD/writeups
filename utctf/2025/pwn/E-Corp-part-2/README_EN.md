# E-Corp part 2
## vulnerability:
By `.confuse()` method we could swap representation of array's elements.
Useful links: 
- https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/ - problem that in 2020 year google added [pointer compression](https://stackoverflow.com/questions/73777790/how-v8-encodes-pointers-in-memory), and writeup's method was not working, but building primitives same.
- https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html - about pointer compression and how to exploit

## Exploiting:
- Craft `addrof` primitive by adding object to array, calling `.confuse()` and reading the pointer as `double`
- Craft `fakeobj` primitive by adding pointer as `double` to array, calling `.confuse()` and getting this element as `Object` class
- Leak map float array pointer by `addrof` primitive on 1 element array
- Craft fake object by 2 doubles in array to get arbitrary read and write on heap object by controlling elements pointer
- Craft fully functioning AR/AW primitives by DataView as in writeup above
- Leak heap, stack, PIE, libc
- Rewrite `__free_hook` to system
- Call `console.log("/bin/sh")` to trigger `free`