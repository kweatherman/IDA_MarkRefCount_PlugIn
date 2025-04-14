## Mark Reference Counts IDA Pro Plug-In

Kevin Weatherman aka "Sirmabus"
Repo [Github](https://github.com/kweatherman/IDA_ClassInformer_PlugIn), former: [SourceForge](https://sourceforge.net/projects/idamarkrefcountplugin/)

A simple IDA Pro plug-in that adds reference count comments for functions and optionally data references in your IDB.

----
### Introduction

This plug-in enumerates functions and, optionally, data references in an IDA database (IDB) and adds repeatable comments with their reference counts. Reference counts provide insights into code and data significance:

- **Functions**: A single reference suggests a local function, while many references may indicate a common utility or support role.
- **Data**: Reference counts for strings, asserts, or debug labels can reveal their importance or usage patterns.

For related tools, check out other my informational plug-ins, such as the "Extra Pass" plug-in, etc.

----

### Installation

1. Copy the plug-in binary to your IDA Pro plugins directory.
2. Edit "plugins.cfg" to assign a hotkey for running the plug-in. Refer to IDA Pro's documentation for detailed plug-in setup instructions.

----
### Usage

1. **Optionally backup your IDB**: Save or back up your database as it might make too many changes for IDA's "undo" feature.
2. **Run the plug-in**: Launch it and select whether to comment on functions, data references, or both.
3. **Proceed**: Click continue to process. The plug-in is optimized for speed, even on large IDBs.

Upon completion, functions and/or data references will have reference counts added as repeatable comments. See the example image in the original documentation for reference.

----
### Operational Notes

- **Quality**: The accuracy of comments depends on the completeness and cleanliness of your IDB. Missing references may lead to incorrect counts (e.g., a function appearing "local" with a count of 1 when it has more).
- **Prerequisites**: For large or messy IDBs with unprocessed blocks, run the "Extra Pass" plug-in first to improve results.
- **Comment Order**: If using other comment-adding plug-ins, run them before this one to ensure reference counts appear at the start of comments.
  The order I typically run them in:
  1. "Function String Associate"
  2. "Mark Reference Counts"
  3. "WhatAPIs"
- **Function Counting**:
  - Counts references to each function.
  - Prefixes counts to existing comments or creates new ones.
  - Skips functions with no references (e.g., disconnected C++ vftable members).
- **Data Counting**:
  - Only counts data with code references (ignores data-to-data references).
  - For strings without comments, the string content is suffixed to the count (e.g., ; 2 'Some random string'), preserving IDA's default string display behavior.
  - No comments are added for single-reference data (since v1.7).


----

##### License

**MIT License**
Copyright © 2009–present Kevin Weatherman  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

See [MIT License](http://www.opensource.org/licenses/mit-license.php) for full details.