RADIUS module
=============

The RADIUS module provides a single authentication module:

`radius:Radius`
: Authenticate a user against a RADIUS server.

This authentication module contacts a RADIUS server, and authenticates
the user by using username & password authentication.

To use this module, enable the radius module: in `config.php`, search
for the `module.enable` key and set `radius` to true:

```php
    'module.enable' => [
         'radius' => true,
         …
    ],
```

Then you need to add a authentication source which uses the `radius:Radius`
module to `config/authsources.php`:

```php
    'example-radius' => [
        'radius:Radius',

        /*
         * An array with the radius servers to use, up to 10.
         * The options are:
         *  - hostname: the hostname of the radius server, or its IP address. Required.
         *  - port: the port of the radius server. Optional, defaults to 1812.
         *  - secret: the radius secret to use with this server. Required.
         */
        'servers' => [
            [
                'hostname' => 'radius1.example.org',
                'port' => 1812,
                'secret' => 'topsecret'
            ],
            [
                'hostname' => 'radius2.example.org',
                'port' => 1812,
                'secret' => 'topsecret'
            ]
        ],

        /*
         * The timeout for contacting the RADIUS server, in seconds.
         * Optional, defaults to 5 seconds.
         */
        'timeout' => 5,

        /*
         * Set debug modus
         */
        'debug' => true,

        /*
         * The NAS identifier to use when querying the radius server.
         * Optional, defaults to the current host name.
         */
        'nas_identifier' => 'client.example.org',

        /*
         * An optional realm that will be suffixed to the username entered
         * by the user. When set to "example.edu", and the user enters
         * "bob" as their username, the radius server will be queried for
         * the username "bob@example.edu".
         * Optional, defaults to NULL.
         */
        'realm' => 'example.edu',

        /*
         * The attribute name we should store the username in. This username
         * will not be saved in any attribute if this is NULL.
         * Optional, defaults to NULL.
         */
        'username_attribute' => 'eduPersonPrincipalName',
    ],
```

User attributes
---------------

If the RADIUS server is configured to include attributes for the user in
the response, this module may be able to extract them. This requires the
attributes to be stored in a vendor-specific attribute in the response
from the RADIUS server.

The code expects one vendor-attribute with a specific vendor and a specific
vendor attribute type for each user attribute. The vendor-attribute must
contain a value of the form `<name>=<value>`.

The following configuration options are available for user attributes:

```php
        /*
         * This is the vendor for the vendor-specific attribute which contains
         * the attributes for this user. This can be NULL if no attributes are
         * included in the response.
         * Optional, defaults to NULL.
         */
        'attribute_vendor' => 23735,

        /*
         * The vendor attribute-type of the attribute which contains the
         * attributes for the user.
         * Required if 'vendor' is set.
         */
        'attribute_vendor_type' => 4,
```
