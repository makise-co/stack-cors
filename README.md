# Stack/Cors
Fork of https://github.com/asm89/stack-cors that allows to use original package in the Makise Framework.

Library and middleware enabling cross-origin resource sharing for your
http-{foundation,kernel} using application. It attempts to implement the
[W3C Recommendation] for cross-origin resource sharing.

[W3C Recommendation]: http://www.w3.org/TR/cors/

Build status: ![.github/workflows/run-tests.yml](https://github.com/asm89/stack-cors/workflows/.github/workflows/run-tests.yml/badge.svg)

## Installation

Require `makise-co/stack-cors` using composer.

## Usage

* Create `cors.php` config in your config directory
* Add `CorsServiceProvider` to the `config/app.php` "providers" section
* Add `CorsMiddleware` to the `config/http.php` "middleware" section

### Options

| Option                 | Description                                                | Default value |
|------------------------|------------------------------------------------------------|---------------|
| allowedMethods         | Matches the request method.                                | `array()`     |
| allowedOrigins         | Matches the request origin.                                | `array()`     |
| allowedOriginsPatterns | Matches the request origin with `preg_match`.              | `array()`  |
| allowedHeaders         | Sets the Access-Control-Allow-Headers response header.     | `array()`     |
| exposedHeaders         | Sets the Access-Control-Expose-Headers response header.    | `false`       |
| maxAge                 | Sets the Access-Control-Max-Age response header.           | `false`       |
| supportsCredentials    | Sets the Access-Control-Allow-Credentials header.          | `false`       |

The _allowedMethods_ and _allowedHeaders_ options are case-insensitive.

You don't need to provide both _allowedOrigins_ and _allowedOriginsPatterns_. If one of the strings passed matches, it is considered a valid origin.

If `array('*')` is provided to _allowedMethods_, _allowedOrigins_ or _allowedHeaders_ all methods / origins / headers are allowed.

### Example: config that allows CORS on all paths
```php
return [

    /*
     * You can enable CORS for 1 or multiple paths.
     * Example: ['api/*']
     */
    'paths' => ['*'],

    /*
    * Matches the request method. `[*]` allows all methods.
    */
    'allowedMethods' => ['*'],

    /*
     * Matches the request origin. `[*]` allows all origins.
     */
    'allowedOrigins' => ['*'],

    /*
     * Matches the request origin with, similar to `Request::is()`
     */
    'allowedOriginsPatterns' => [],

    /*
     * Sets the Access-Control-Allow-Headers response header. `[*]` allows all headers.
     */
    'allowedHeaders' => ['*'],

    /*
     * Sets the Access-Control-Expose-Headers response header.
     */
    'exposedHeaders' => false,

    /*
     * Sets the Access-Control-Max-Age response header.
     */
    'maxAge' => 600,

    /*
     * Sets the Access-Control-Allow-Credentials header.
     */
    'supportsCredentials' => true,

];
```

### Example: using the library

```php
<?php

use Asm89\Stack\CorsService;

$cors = new CorsService(array(
    'allowedHeaders'         => array('x-allowed-header', 'x-other-allowed-header'),
    'allowedMethods'         => array('DELETE', 'GET', 'POST', 'PUT'),
    'allowedOrigins'         => array('http://localhost'),
    'allowedOriginsPatterns' => array('/localhost:\d/'),
    'exposedHeaders'         => false,
    'maxAge'                 => false,
    'supportsCredentials'    => false,
));

$cors->addActualRequestHeaders(Response $response, $origin);
$cors->handlePreflightRequest(Request $request);
$cors->isActualRequestAllowed(Request $request);
$cors->isCorsRequest(Request $request);
$cors->isPreflightRequest(Request $request);
```

