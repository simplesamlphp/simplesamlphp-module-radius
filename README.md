# Module for RADIUS authentication

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-radius/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-radius/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-radius)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-radius/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-radius/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-radius/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-radius)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-radius/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-radius)

This module provides an authentication source for interaction with Radius servers.

## Installation

Once you have installed SimpleSAMLphp, installing this module is very simple.
Just execute the following command in the root of your SimpleSAMLphp
installation:

```bash
composer.phar require simplesamlphp/simplesamlphp-module-radius:dev-master
```

where `dev-master` instructs Composer to install the `master` branch from the
Git repository. See the [releases](https://github.com/simplesamlphp/simplesamlphp-module-radius/releases)
available if you want to use a stable version of the module.

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `radius` to true:

```php
    'module.enable' => [
         'radius' => true,
         …
    ],
```
