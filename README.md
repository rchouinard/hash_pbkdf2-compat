# PHP PBKDF2 Compatibility Functions

This component provides compatibility for the `hash_pbkdf2()` function on PHP
versions >=5.3,<5.5.

## Quick start

Installation is supported via [Composer](http://getcomposer.org/) or [Git](http://git-scm.com/). After installation,
just `include`/`require` the appropriate file in your application and start using the functions.

 1. Install via Composer:

    ```bash
    curl -sS https://getcomposer.org/installer | php
    php composer.phar require rych/hash_pbkdf2-compat 1.0.*
    ```
    ```php
    <?php
    require 'vendor/autoload.php';
    ```

 2. Install via Git:

    ```bash
    git clone https://github.com/rchouinard/hash_pbkdf2-compat.git
    git checkout tags/v1.0.0
    ```
    ```php
    <?php
    require 'hash_pbkdf2-compat/src/hash_pbkdf2_compat.php';
    ```

## Usage

The component provides the function `\Rych\hash_pbkdf2()`, which works exactly
like the `[hash_pbkdf2()](http://php.net/manual/en/function.hash-pbkdf2.php)`
function provided in PHP 5.5.

For PHP versions <5.5, the component will also register `\hash_pbkdf2()` as an
alias to `\Rych\hash_pbkdf2()`.
