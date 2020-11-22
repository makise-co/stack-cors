<?php

/*
 * This file is part of asm89/stack-cors.
 *
 * (c) Alexander <iam.asm89@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Asm89\Stack;

use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function array_map;
use function array_values;
use function explode;
use function implode;
use function in_array;
use function preg_match;

class CorsService
{
    private array $options;

    public function __construct(array $options = [])
    {
        $this->options = $this->normalizeOptions($options);
    }

    private function normalizeOptions(array $options = []): array
    {
        $options += [
            'allowedOrigins' => [],
            'allowedOriginsPatterns' => [],
            'supportsCredentials' => false,
            'allowedHeaders' => [],
            'exposedHeaders' => [],
            'allowedMethods' => [],
            'maxAge' => '0',
        ];

        // normalize array('*') to true
        if (in_array('*', $options['allowedOrigins'], true)) {
            $options['allowedOrigins'] = true;
        }
        if (in_array('*', $options['allowedHeaders'], true)) {
            $options['allowedHeaders'] = true;
        } else {
            $options['allowedHeaders'] = array_map('strtolower', $options['allowedHeaders']);
        }

        if (in_array('*', $options['allowedMethods'], true)) {
            $options['allowedMethods'] = true;
        } else {
            $options['allowedMethods'] = array_map('strtoupper', $options['allowedMethods']);
        }

        if (null !== $options['maxAge']) {
            $options['maxAge'] = (string)$options['maxAge'];
        }

        return $options;
    }

    public function isCorsRequest(ServerRequestInterface $request): bool
    {
        return $request->getHeader('Origin') && !$this->isSameHost($request);
    }

    public function isPreflightRequest(ServerRequestInterface $request): bool
    {
        return $request->getMethod() === 'OPTIONS' && $request->getHeader('Access-Control-Request-Method');
    }

    public function handlePreflightRequest(ServerRequestInterface $request): ResponseInterface
    {
        $response = new TextResponse('', 204);

        return $this->addPreflightRequestHeaders($response, $request);
    }

    public function addPreflightRequestHeaders(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->configureAllowedOrigin($response, $request);

        if ($response->hasHeader('Access-Control-Allow-Origin')) {
            $response = $this->configureAllowCredentials($response, $request);

            $response = $this->configureAllowedMethods($response, $request);

            $response = $this->configureAllowedHeaders($response, $request);

            $response = $this->configureMaxAge($response, $request);
        }

        return $response;
    }

    public function isOriginAllowed(ServerRequestInterface $request): bool
    {
        if ($this->options['allowedOrigins'] === true) {
            return true;
        }

        if (empty($origin = $request->getHeaderLine('Origin'))) {
            return false;
        }

        if (in_array($origin, $this->options['allowedOrigins'], true)) {
            return true;
        }

        foreach ($this->options['allowedOriginsPatterns'] as $pattern) {
            if (preg_match($pattern, $origin)) {
                return true;
            }
        }

        return false;
    }

    public function addActualRequestHeaders(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->configureAllowedOrigin($response, $request);

        if ($response->hasHeader('Access-Control-Allow-Origin')) {
            $response = $this->configureAllowCredentials($response, $request);
            $response = $this->configureExposedHeaders($response, $request);
        }

        return $response;
    }

    private function configureAllowedOrigin(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['allowedOrigins'] === true && !$this->options['supportsCredentials']) {
            // Safe+cacheable, allow everything
            $response = $response->withHeader('Access-Control-Allow-Origin', '*');
        } elseif ($this->isSingleOriginAllowed()) {
            // Single origins can be safely set
            $response = $response->withHeader('Access-Control-Allow-Origin', array_values($this->options['allowedOrigins'])[0]);
        } else {
            // For dynamic headers, check the origin first
            if ($this->isOriginAllowed($request)) {
                $origin = $request->getHeader('Origin');
                if (!empty($origin)) {
                    $response = $response->withHeader('Access-Control-Allow-Origin', $origin);
                }
            }

            $response = $this->varyHeader($response, 'Origin');
        }

        return $response;
    }

    private function isSingleOriginAllowed(): bool
    {
        if ($this->options['allowedOrigins'] === true || !empty($this->options['allowedOriginsPatterns'])) {
            return false;
        }

        return count($this->options['allowedOrigins']) === 1;
    }

    private function configureAllowedMethods(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['allowedMethods'] === true) {
            if ($this->options['supportsCredentials']) {
                $allowMethods = strtoupper($request->getHeaderLine('Access-Control-Request-Method'));
                $response = $this->varyHeader($response, 'Access-Control-Request-Method');
            } else {
                $allowMethods = '*';
            }
        } else {
            $allowMethods = $this->options['allowedMethods'];
        }

        if (!empty($allowMethods)) {
            return $response->withHeader('Access-Control-Allow-Methods', $allowMethods);
        }

        return $response;
    }

    private function configureAllowedHeaders(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['allowedHeaders'] === true) {
            if ($this->options['supportsCredentials']) {
                $allowHeaders = $request->getHeader('Access-Control-Request-Headers');
                $response = $this->varyHeader($response, 'Access-Control-Request-Headers');
            } else {
                $allowHeaders = '*';
            }
        } else {
            $allowHeaders = $this->options['allowedHeaders'];
        }

        if (!empty($allowHeaders)) {
            return $response->withHeader('Access-Control-Allow-Headers', $allowHeaders);
        }

        return $response;
    }

    private function configureAllowCredentials(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['supportsCredentials']) {
            return $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        return $response;
    }

    private function configureExposedHeaders(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['exposedHeaders']) {
            return $response->withHeader('Access-Control-Expose-Headers', implode(', ', $this->options['exposedHeaders']));
        }

        return $response;
    }

    private function configureMaxAge(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->options['maxAge'] !== null) {
            return $response->withHeader('Access-Control-Max-Age', $this->options['maxAge']);
        }

        return $response;
    }

    public function varyHeader(ResponseInterface $response, string $header): ResponseInterface
    {
        if (!$response->hasHeader('Vary')) {
            $response = $response->withHeader('Vary', $header);
        } elseif (!in_array($header, explode(',', $response->getHeaderLine('Vary')), true)) {
            $response = $response->withAddedHeader('Vary', $header);
        }

        return $response;
    }

    private function isSameHost(ServerRequestInterface $request): bool
    {
        $uri = $request->getUri();
        $path = "{$uri->getScheme()}://{$uri->getHost()}";

        return $request->getHeaderLine('Origin') === $path;
    }
}
