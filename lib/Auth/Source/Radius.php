<?php

declare(strict_types=1);

namespace SimpleSAML\Module\radius\Auth\Source;

use Exception;
use Dapphp\Radius\Radius as RadiusClient;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Utils;

/**
 * RADIUS authentication source.
 *
 * This class is based on www/auth/login-radius.php.
 *
 * @package SimpleSAMLphp
 */
class Radius extends UserPassBase
{
    /**
     * @var array The list of radius servers to use.
     */
    private array $servers;

    /**
     * @var string The hostname of the radius server.
     */
    private string $hostname;

    /**
     * @var int The port of the radius server.
     */
    private int $port;

    /**
     * @var string The secret used when communicating with the radius server.
     */
    private string $secret;

    /**
     * @var int The timeout for contacting the radius server.
     */
    private int $timeout;

    /**
     * @var string|null The realm to be added to the entered username.
     */
    private ?string $realm;

    /**
     * @var string|null The attribute name where the username should be stored.
     */
    private ?string $usernameAttribute = null;

    /**
     * @var int|null The vendor for the RADIUS attributes we are interrested in.
     */
    private ?int $vendor = null;

    /**
     * @var int The vendor-specific attribute for the RADIUS attributes we are
     *     interrested in.
     */
    private int $vendorType;

    /**
     * @var string|null The NAS-Identifier that should be set in Access-Request packets.
     */
    private ?string $nasIdentifier = null;

    /**
     * @var bool Debug modus
     */
    private bool $debug;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Parse configuration.
        $cfg = Configuration::loadFromArray(
            $config,
            'Authentication source ' . var_export($this->authId, true)
        );

        $this->servers = $cfg->getOptionalArray('servers', []);
        // For backwards compatibility
        if (empty($this->servers)) {
            $this->hostname = $cfg->getString('hostname');
            $this->port = $cfg->getOptionalIntegerRange('port', 1, 65535, 1812);
            $this->secret = $cfg->getString('secret');
            $this->servers[] = [
                'hostname' => $this->hostname,
                'port' => $this->port,
                'secret' => $this->secret
            ];
        }
        $this->debug = $cfg->getOptionalBoolean('debug', false);
        $this->timeout = $cfg->getOptionalInteger('timeout', 5);
        $this->realm = $cfg->getOptionalString('realm', null);
        $this->usernameAttribute = $cfg->getOptionalString('username_attribute', null);
        $this->nasIdentifier = $cfg->getOptionalString('nas_identifier', null);

        $this->vendor = $cfg->getOptionalInteger('attribute_vendor', null);
        if ($this->vendor !== null) {
            $this->vendorType = $cfg->getInteger('attribute_vendor_type');
        }
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array[] Associative array with the user's attributes.
     */
    protected function login(string $username, string $password): array
    {
        $radius = new RadiusClient();

        // Try to add all radius servers, trigger a failure if no one works
        $success = false;
        foreach ($this->servers as $server) {
            $radius->setServer($server['hostname']);
            $radius->setAuthenticationPort($server['port']);
            $radius->setSecret($server['secret']);
            $radius->setDebug($this->debug);
            $radius->setTimeout($this->timeout);

            $httpUtils = new Utils\HTTP();
            $radius->setNasIpAddress(->setAuthenticationPort($httpUtils->getSelfHost());

            if ($this->nasIdentifier !== null) {
                $radius->setAttribute(32, $this->nasIdentifier);
            }

            if ($this->realm === null) {
                $this->setRadiusSuffix($this->realm);
            }
            $response = $radius->accessRequest($username, $password);

            if ($response !== false) {
                break;
            }
        }

        if ($response === false) {
            throw new Exception('Error during radius authentication.');
        }

        // If we get this far, we have a valid login

        $attributes = [];
        $usernameAttribute = $this->usernameAttribute;

        if ($usernameAttribute !== null) {
            $attributes[$usernameAttribute] = [$username];
        }

        if ($this->vendor === null) {
            /*
             * We aren't interested in any vendor-specific attributes. We are
             * therefore done now.
             */
            return $attributes;
        }

        // get AAI attribute sets.
        while ($resa = $radius->getAttributes()) {
            if (!is_array($resa)) {
                throw new Exception(
                    'Error getting radius attributes: ' . radius_strerror($radius)
                );
            }

            // Use the received user name
            if ($resa['attr'] === 1 && $usernameAttribute !== null) {
                $attributes[$usernameAttribute] = [$resa['data']];
                continue;
            }

            if ($resa['attr'] !== 26) { // Vendor-specific
                continue;
            }

            $resv = $resa['data'];
            if ($resv === false) {
                throw new Exception(
                    'Error getting vendor specific attribute'
                );
            }

            $vendor = $resv['vendor'];
            $attrv = $resv['attr'];
            $datav = $resv['data'];

            if ($vendor !== $this->vendor || $attrv !== $this->vendorType) {
                continue;
            }

            $attrib_name = strtok($datav, '=');
            /** @psalm-suppress TooFewArguments */
            $attrib_value = strtok('=');

            // if the attribute name is already in result set, add another value
            if (array_key_exists($attrib_name, $attributes)) {
                $attributes[$attrib_name][] = $attrib_value;
            } else {
                $attributes[$attrib_name] = [$attrib_value];
            }
        }

        return $attributes;
    }
}
