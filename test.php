<?php

function ip2bin($ip)
{
    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false)
        return base_convert(ip2long($ip),10,2);
    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false)
        return false;
    if(($ip_n = inet_pton($ip)) === false) return false;
    $bits = 15;
    $ipbin = '';
    while ($bits >= 0) {
        $bin = sprintf("%08b",(ord($ip_n[$bits])));
        $ipbin = $bin.$ipbin;
        $bits--;
    }
    return $ipbin;
}

echo ip2bin('4ffe:2900:5545:3210:2000:f8ff:fe21:67cf');

// Outputs:
// 01001111111111100010100100000000010101010100010100110010000100000010000000000000111110001111111111111110001000010110011111001111
