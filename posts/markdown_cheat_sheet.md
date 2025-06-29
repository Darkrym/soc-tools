
---
author:
  name: "Darkrym"
date: 2025-06-10
linktitle: Markdown Analysis
type:
- post
- posts
title: Markdown Cheatsheet
weight: 10
series:
- cheat_sheets
---
Content from [The Markdown Guide](https://www.markdownguide.org/ "https://www.markdownguide.org")

# Basic Syntax
```
# Heading 1  
## Heading 2  
### Heading 3  

**bold text**  
*italicized text*  

> blockquote  

1. First item  
2. Second item  
3. Third item  

- First item  
- Second item  
- Third item  

`code`  

---  

[Markdown Guide](https://www.markdownguide.org)  

![alt text](https://www.markdownguide.org/assets/images/tux.png) 
```

Rendered:

# Heading 1  
## Heading 2  
### Heading 3  


**bold text**  

*italicized text*  

> blockquote  

1. First item  
2. Second item  
3. Third item  

- First item  
- Second item  
- Third item  

`code`  

---  

[Markdown Guide](https://www.markdownguide.org)  

![alt text](https://www.markdownguide.org/assets/images/tux.png) 

# Extended Syntax
```
| Syntax     | Description |
|------------|-------------|
| Header     | Title       |
| Paragraph  | Text        |

```json                                            # Fenced Code Block
{
  "firstName": "John",
  "lastName": "Smith",
  "age": 25
} ```

Here's a sentence with a footnote. 1
[^1]: This is the footnote.

### My Great Heading {#custom-id}`|                  # Creating an ID to refer to headings with

term
: definition

~~The world is flat.~~                                # Strike Through

I need to highlight these ==very important words==.

- [x] Write the press release                         # Task List
- [ ] Update the website  
- [ ] Contact the media

That is so funny! :joy:                               # Emoji

H~2~O                                                 # Subscript
X^2^                                                  # Superscript
```

Rendered (The one my website can render atleast):

| Syntax     | Description |
|------------|-------------|
| Header     | Title       |
| Paragraph  | Text        |

```json
{
  "firstName": "John",
  "lastName": "Smith",
  "age": 25
} 
```

Here's a sentence with a footnote. 1
[^1]: This is the footnote.

### My Great Heading {#custom-id}

~~The world is flat.~~

- [x] Write the press release                        
- [ ] Update the website  
- [ ] Contact the media

---
## Useful Tools

| Tool                      | Purpose / Description                                              |
| ------------------------- | ------------------------------------------------------------------ |
| Obsidian                  | Note-taking app using Markdown files with powerful linking         |
| Visual Studio Code        | Code editor with Markdown preview and extensions                   |
| Markdown Preview Enhanced | VS Code extension for advanced Markdown rendering                  |
| Grip                      | GitHub Readme Instant Preview — renders Markdown as GitHub would   |
| Pandoc                    | Converts Markdown to/from many formats (PDF, DOCX, HTML, LaTeX...) |
| MarkdownLint              | Linter for Markdown — checks style, formatting rules               |
| mdBook                    | Create books or documentation from Markdown files                  |
| Docsify                   | Generate docs websites from Markdown files                         |
| markdown-pdf              | CLI tool to convert Markdown to PDF using Node.js                  |
