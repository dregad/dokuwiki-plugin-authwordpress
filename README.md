# authwordpress - an authentication plugin for DokuWiki

Provides authentication against a WordPress MySQL database backend.

Copyright (c) 2015 Damien Regad <dregad@mantisbt.org>

> [!WARNING]
> Please note that I no longer actively use this plugin.
>
> I intend to continue maintaining it, but will not proactively test it
> against the latest DokuWiki and WordPress releases.
>
> It has been pretty stable over the years so I do not expect problems,
> but should you experience difficulties, please open a
> [new Issue](https://github.com/dregad/dokuwiki-plugin-authwordpress/issues/new/choose)
> or even better, send a patch with a
> [Pull Request](https://github.com/dregad/dokuwiki-plugin-authwordpress/compare).


## License

This program is free software; you can redistribute it and/or modify
it under the terms of the
[GNU General Public License, version 2](http://www.gnu.org/licenses/gpl-2.0.html)
or later.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.


## Installation and Configuration

Please refer to the [plugin's documentation](http://www.dokuwiki.org/plugin:authwordpress)
for information on how to install and configure this plugin in DokuWiki.

If you install this plugin manually, make sure it is installed in
`lib/plugins/authwordpress/` - if the folder is called differently,
it will not work!


## Compatibility

PHP 7.4 or later is required.

### DokuWiki

This plugin has been tested with the following DokuWiki releases:

- 2025-05-14b "Librarian"
- 2024-02-06b “Kaos”

Plugin version 2026-06-16 dropped support for older DokuWiki releases.

Use version **2025-05-29** for compatibility with:
- 2023-04-04a “Jack Jackrum”
- 2022-07-31b “Igor”

Use version **2020-03-14** for compatibility with:
- 2020-07-29a “Hogfather”
- 2018-04-22b “Greebo”
- 2017-02-19e “Frusterick Manners”
- 2016-06-26e “Elenor of Tsort”
- 2015-08-10a “Detritus”

It will probably also work with *2013-05-10 “Weatherwax”* and later.

### WordPress

On the back-end side, the plugin supports WordPress releases 4.x to 7.x.
It has been tested and confirmed to work on versions
4.3 to 4.9, 5.1 to 5.9, 6.0 to 6.9, 7.0.


## Support

Source code and support for this plugin can be found at
https://github.com/dregad/dokuwiki-plugin-authwordpress
