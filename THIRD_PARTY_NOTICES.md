# Third-Party Notices

Lethe source written for this repository is copyright 2026 zaehuncho and
is licensed under the Apache License 2.0. The repository also includes or uses
the third-party software below. Those components remain governed by their own
licenses; the Apache License 2.0 does not replace them.

## Included source

### miniz 3.0.0

Lethe compiles miniz source in `stub/src/miniz.c` and `stub/src/miniz.h` into
the native stub. Upstream: <https://github.com/richgel999/miniz>. License notice:

> Copyright 2013-2014 RAD Game Tools and Valve Software  
> Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC  
> All Rights Reserved.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
> THE SOFTWARE.

## Python dependencies

Python packages are downloaded into the development environment from the
versions fixed in `uv.lock`; their source is not copied into this repository.
The following is a convenience inventory, not a substitute for the license
files shipped by each package:

| Package | Use | License summary |
| --- | --- | --- |
| argon2-cffi | Development/test | MIT |
| certifi | Runtime/build | MPL-2.0 |
| cryptography | Runtime/build | Apache-2.0 OR BSD-3-Clause |
| iced-x86 | Development/test | MIT |
| LIEF | Runtime/build | Apache-2.0 |
| Nuitka | Optional GUI freezing | Apache-2.0 |
| pytest | Development/test | MIT |
| PySide6 / Qt for Python | Optional GUI development and freezing | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only, or a commercial Qt license |
| keystone-engine | Development/test | GPL-2.0 for the Keystone engine; BSD-3-Clause for its Python binding |
| Unicorn | Development/test | GPL-2.0 for the Unicorn engine; bindings may carry separate terms |

Project and license references:

- Qt for Python licensing: <https://doc.qt.io/qtforpython-6/licenses.html>
- Keystone Engine: <https://github.com/keystone-engine/keystone>
- Unicorn Engine: <https://github.com/unicorn-engine/unicorn>
- Remaining package metadata and license files are available through their
  linked project pages on <https://pypi.org/>.

Anyone distributing a frozen GUI or other binary bundle must include the
license texts and notices shipped with the exact wheels and native libraries in
that bundle and satisfy the applicable source/relinking requirements. The
repository notice alone is not sufficient for binary redistribution.
