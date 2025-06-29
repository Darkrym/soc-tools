---
author:
  name: Darkrym
date: 2025-06-27
linktitle: Regex
type:
  - post
  - posts
title: Regex Cheat Sheet
weight: 11
series:
  - cheat_sheets
---

This regex reference outlines essential components for pattern matching, capturing, and string manipulation, drawn from DaveChild’s widely used Regular Expressions cheat sheet, but adapted for security analysts, blue teamers, and SOC professionals.

---
## The Basics

```
.       # Any character except newline
*       # 0 or more of the previous
+       # 1 or more of the previous
?       # 0 or 1 of the previous
|       # OR operator
()      # Group expressions
[]      # Character class
[^]     # Negated character class
{n,m}   # Repeat n to m times
\d      # Digit (0-9)
\w      # Word character (a-zA-Z0-9_)
\s      # Whitespace
\.      # Escape literal dot with \.
```

## Common IOC Search Patterns

```
https?:\/\/[\w.-]+(?:\/[\w\/._%-]*)?                # Website
[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]       # Email address
\b(?:\d{1,3}\.){3}\d{1,3}\b                         # IPv4 address
([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}              # IPv6 address
[A-Z]:\\(?:[\w\s.-]+\\)*[\w\s.-]+                   # Windows path
\/(?:[\w.-]+\/)*[\w.-]+                             # Unix/Linux path
(["'])([\w\/]+)\1                                   # Variables from scripts
(?:[A-Za-z0-9+/]{4}){2,}(?:==|=)?                   # Base64
```

---
## Tooling Tips

- Use `regex101.com` or **CyberChef** for testing and debugging.
- Double-escape backslashes (`\\`) when pasting into JSON/Sigma rules.
- Use SIEM-specific syntax for anchors (e.g., `^`, `$` may not always be needed).
- Be cautious with overly greedy expressions in detection logic.

---

Useful Tools for Regex

| Tool                                                                            | Use                                     |
| ------------------------------------------------------------------------------- | --------------------------------------- |
| **CyberChef**                                                                   | Decode, deobfuscate, extract strings    |
| **YARA**                                                                        | Combine regex with memory/file scanning |
| **Sigma**                                                                       | Detection rules with regex support      |
| [**Regex101**](https://regex101.com/)                                           | Online regex tester with explanation    |
| **Elastic**                                                                     | Full regex support in queries           |
| [Regexper](https://regexper.com/#%2F%28%3F%3AHKLM%7CHKCU%29%3A%5Ba-z%5D%2B%2Fi) | Regex Visualiser                        |

## Advanced Patterns 
---
Content adapted from DaveChild | More at [https://cheatography.com/](https://cheatography.com/davechild/)
### Anchors  

```
^       Start of string, or start of line in multi-line mode  
\A      Start of string  
$       End of string, or end of line in multi-line mode  
\Z      End of string  
\b      Word boundary  
\B      Not word boundary  
\<      Start of word  
\>      End of word  
```

---

### Character Classes  
```
\c      Control character  
\s      Whitespace  
\S      Not whitespace  
\d      Digit  
\D      Not digit  
\w      Word character  
\W      Not word character  
\x      Hexadecimal digit  
\O      Octal digit  
```

---

### POSIX Character Classes  
```
[:upper:]     Uppercase letters  
[:lower:]     Lowercase letters  
[:alpha:]     All letters  
[:alnum:]     Digits and letters  
[:digit:]     Digits  
[:xdigit:]    Hexadecimal digits  
[:punct:]     Punctuation  
[:blank:]     Space and tab  
[:space:]     Blank characters  
[:cntrl:]     Control characters  
[:graph:]     Printed characters (no space)  
[:print:]     Printed characters and spaces  
[:word:]      Digits, letters and underscore  
```

---

### Assertions  
```ruby
(?=...)       Lookahead assertion  
(?!...)       Negative lookahead  
(?<=...)      Lookbehind assertion  
(?<!...)      Negative lookbehind (also written as ?!=)  
(?>...)       Once-only subexpression  
(?(cond)...)  Condition [if then]  
(?(cond)...|...)  Condition [if then else]  
(?#...)       Comment  
```

---

### Quantifiers  
```markdown
*        0 or more  
+        1 or more  
?        0 or 1  
{3}      Exactly 3  
{3,}     3 or more  
{3,5}    3, 4 or 5  
*? +? ?? {n,m}?  Add ? to make it ungreedy  
```

---

### Escape Sequences  
```pgsql
\        Escape the following character  
\Q       Begin literal sequence  
\E       End literal sequence  
```
> Escaping allows treating special regex characters as literals.

---

### Common Metacharacters  
```ruby
^ [ . $ { * ( \ + ) | ? < >
```
> Escape them with `\` when used literally.

---

### Special Characters  
```pgsql
\n       New line  
\r       Carriage return  
\t       Tab  
\v       Vertical tab  
\f       Form feed  
\xxx     Octal character xxx  
\xhh     Hex character hh  
```

---

### Groups and Ranges  
```less
.           Any character except newline (\n)  
(a|b)       a or b  
(...)       Capturing group  
(?:...)     Non-capturing group  
[abc]       a or b or c  
[^abc]      Not a, b or c  
[a-q]       Lowercase a to q  
[A-Q]       Uppercase A to Q  
[0-7]       Digit 0 to 7  
\1, \2, ... Refer to matched group 1, 2, etc.  
```
> Ranges are inclusive.

---

### Pattern Modifiers (Flags)  
```vbnet
g    Global match  
i    Case-insensitive  
m    Multi-line mode  
s    Treat string as single line (dot matches newline)  
x    Allow comments and whitespace  
e    Evaluate replacement (rare/legacy use)  
U    Make quantifiers ungreedy by default  
```
> Flags are applied outside the pattern, like `/pattern/gi`

---

### String Replacement  
```vbnet
$n      nth non-passive group  
$1      First captured group  
$2      Second captured group  
$&      Entire matched string  
$`      Text before the match  
$'      Text after the match  
$+      Last matched group  
```
> Some engines use `\1`, `\2`, etc., instead of `$1`, `$2`.

---
