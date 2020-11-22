<?php

/*
 * This file is part of asm89/stack-cors.
 *
 * (c) Alexander <iam.asm89@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Asm89\Stack\Tests;

use Asm89\Stack\CorsMiddleware;
use Asm89\Stack\CorsService;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CorsTest extends TestCase
{
    /**
     * @test
     */
    public function it_does_modify_on_a_request_without_origin(): void
    {
        $app = $this->createStackedApp();

        $response = $app->process(new ServerRequest(), $this->getRequestHandler([]));

        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_does_modify_on_a_request_with_same_origin(): void
    {
        $app = $this->createStackedApp(['allowedOrigins' => ['*']]);

        $request = (new ServerRequest())
            ->withHeader('Host', 'foo.com')
            ->withHeader('Origin', 'http://foo.com');
        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_returns_allow_origin_header_on_valid_actual_request(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_returns_allow_origin_header_on_allow_all_origin_request(): void
    {
        $app = $this->createStackedApp(['allowedOrigins' => ['*']]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_returns_allow_headers_header_on_allow_all_headers_request(): void
    {
        $app = $this->createStackedApp(['allowedHeaders' => ['*']]);
        $request = $this->createValidPreflightRequest()
            ->withHeader('Access-Control-Request-Headers', ['Foo', 'BAR']);

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals(204, $response->getStatusCode());
        $this->assertEquals('*', $response->getHeaderLine('Access-Control-Allow-Headers'));
    }

    /**
     * @test
     */
    public function it_returns_allow_headers_header_on_allow_all_headers_request_credentials(): void
    {
        $app = $this->createStackedApp(['allowedHeaders' => ['*'], 'supportsCredentials' => true]);
        $request = $this->createValidPreflightRequest()
            ->withHeader('Access-Control-Request-Headers', ['Foo', 'BAR']);

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals(204, $response->getStatusCode());
        $this->assertEquals(['Foo', 'BAR'], $response->getHeader('Access-Control-Allow-Headers'));
        $this->assertEquals('Access-Control-Request-Headers,Access-Control-Request-Method',
            $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_sets_allow_credentials_header_when_flag_is_set_on_valid_actual_request(): void
    {
        $app = $this->createStackedApp(['supportsCredentials' => true]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Credentials'));
        $this->assertEquals('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function it_does_not_set_allow_credentials_header_when_flag_is_not_set_on_valid_actual_request(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function it_sets_exposed_headers_when_configured_on_actual_request(): void
    {
        $app = $this->createStackedApp(['exposedHeaders' => ['x-exposed-header', 'x-another-exposed-header']]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Expose-Headers'));
        $this->assertEquals('x-exposed-header, x-another-exposed-header',
            $response->getHeaderLine('Access-Control-Expose-Headers'));
    }

    /**
     * @test
     */
    public function it_adds_a_vary_header_when_wildcard_and_supports_credentials(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => ['*'],
            'supportsCredentials' => true,
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Vary'));
        $this->assertEquals('Origin', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_adds_multiple_vary_header_when_wildcard_and_supports_credentials(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => ['*'],
            'allowedMethods' => ['*'],
            'supportsCredentials' => true,
        ]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Vary'));
        $this->assertEquals('Origin,Access-Control-Request-Method', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_adds_a_vary_header_when_has_origin_patterns(): void
    {
        $app = $this->createStackedApp([
            'allowedOriginsPatterns' => ['/l(o|0)calh(o|0)st/']
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Vary'));
        $this->assertEquals('Origin', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_doesnt_add_a_vary_header_when_wilcard_origins(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => ['*', 'http://localhost']
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertFalse($response->hasHeader('Vary'));
    }

    /**
     * @test
     */
    public function it_doesnt_add_a_vary_header_when_simple_origins(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => ['http://localhost']
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertFalse($response->hasHeader('Vary'));
    }

    /**
     * @test
     */
    public function it_adds_a_vary_header_when_multiple_origins(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => ['http://localhost', 'http://example.com']
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertTrue($response->hasHeader('Vary'));
    }

    /**
     * @test
     * @see http://www.w3.org/TR/cors/index.html#resource-implementation
     */
    public function it_appends_an_existing_vary_header(): void
    {
        $app = $this->createStackedApp(
            [
                'allowedOrigins' => ['*'],
                'supportsCredentials' => true,
            ]
        );
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler(['Vary' => 'Content-Type']));

        $this->assertTrue($response->hasHeader('Vary'));
        $this->assertEquals('Content-Type,Origin', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_returns_access_control_headers_on_cors_request(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_returns_access_control_headers_on_cors_request_with_pattern_origin(): void
    {
        $app = $this->createStackedApp([
            'allowedOrigins' => [],
            'allowedOriginsPatterns' => ['/l(o|0)calh(o|0)st/']
        ]);
        $request = $this->createValidActualRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertTrue($response->hasHeader('Vary'));
        $this->assertEquals('Origin', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_adds_vary_headers_on_preflight_non_preflight_options(): void
    {
        $app = $this->createStackedApp();
        $request = (new ServerRequest())
            ->withMethod('OPTIONS');

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals('Access-Control-Request-Method', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_returns_access_control_headers_on_valid_preflight_request(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertEquals('Access-Control-Request-Method', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_does_not_allow_request_with_origin_not_allowed(): void
    {
        $passedOptions = [
            'allowedOrigins' => ['http://notlocalhost'],
        ];

        $service = new CorsService($passedOptions);
        $request = $this->createValidActualRequest();
        $response = new TextResponse('');
        $service->addActualRequestHeaders($response, $request);

        $this->assertNotEquals($request->getHeaderLine('Origin'),
            $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_does_not_modify_request_with_pattern_origin_not_allowed(): void
    {
        $passedOptions = [
            'allowedOrigins' => [],
            'allowedOriginsPatterns' => ['/l\dcalh\dst/']
        ];

        $service = new CorsService($passedOptions);
        $request = $this->createValidActualRequest();
        $response = new TextResponse('');
        $service->addActualRequestHeaders($response, $request);

        $this->assertNotEquals($request->getHeaderLine('Origin'),
            $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function it_allow_methods_on_valid_preflight_request(): void
    {
        $app = $this->createStackedApp(['allowedMethods' => ['get', 'put']]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Methods'));
        // it will uppercase the methods
        $this->assertEquals('GET,PUT', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    /**
     * @test
     */
    public function it_returns_valid_preflight_request_with_allow_methods_all(): void
    {
        $app = $this->createStackedApp(['allowedMethods' => ['*']]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Methods'));
        // it will return the Access-Control-Request-Method pass in the request
        $this->assertEquals('*', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    /**
     * @test
     */
    public function it_returns_valid_preflight_request_with_allow_methods_all_credentials(): void
    {
        $app = $this->createStackedApp(['allowedMethods' => ['*'], 'supportsCredentials' => true]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Methods'));
        // it will return the Access-Control-Request-Method pass in the request
        $this->assertEquals('GET', $response->getHeaderLine('Access-Control-Allow-Methods'));
        // it should vary this header
        $this->assertEquals('Access-Control-Request-Method', $response->getHeaderLine('Vary'));
    }

    /**
     * @test
     */
    public function it_returns_ok_on_valid_preflight_request_with_requested_headers_allowed(): void
    {
        $app = $this->createStackedApp();
        $requestHeaders = 'X-Allowed-Header, x-other-allowed-header';
        $request = $this->createValidPreflightRequest()
            ->withHeader('Access-Control-Request-Headers', $requestHeaders);

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertEquals(204, $response->getStatusCode());

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Headers'));
        // the response will have the "allowedHeaders" value passed to Cors rather than the request one
        $this->assertEquals('x-allowed-header,x-other-allowed-header',
            $response->getHeaderLine('Access-Control-Allow-Headers'));
    }

    /**
     * @test
     */
    public function it_sets_allow_credentials_header_when_flag_is_set_on_valid_preflight_request(): void
    {
        $app = $this->createStackedApp(['supportsCredentials' => true]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Allow-Credentials'));
        $this->assertEquals('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function it_does_not_set_allow_credentials_header_when_flag_is_not_set_on_valid_preflight_request(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function it_sets_max_age_when_set(): void
    {
        $app = $this->createStackedApp(['maxAge' => 42]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Max-Age'));
        $this->assertEquals(42, $response->getHeaderLine('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function it_sets_max_age_when_zero(): void
    {
        $app = $this->createStackedApp(['maxAge' => 0]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertTrue($response->hasHeader('Access-Control-Max-Age'));
        $this->assertEquals(0, $response->getHeaderLine('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function it_doesnt_set_max_age_when_false(): void
    {
        $app = $this->createStackedApp(['maxAge' => null]);
        $request = $this->createValidPreflightRequest();

        $response = $app->process($request, $this->getRequestHandler([]));

        $this->assertFalse($response->hasHeader('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function it_skips_empty_access_control_request_header(): void
    {
        $app = $this->createStackedApp();
        $request = $this->createValidPreflightRequest()
            ->withHeader('Access-Control-Request-Headers', '');

        $response = $app->process($request, $this->getRequestHandler([]));
        $this->assertEquals(204, $response->getStatusCode());
    }

    private function createValidActualRequest(): ServerRequestInterface
    {
        return (new ServerRequest())
            ->withHeader('Origin', 'http://localhost');
    }

    private function createValidPreflightRequest(): ServerRequestInterface
    {
        return (new ServerRequest())
            ->withHeader('Origin', 'http://localhost')
            ->withHeader('Access-Control-Request-Method', 'GET')
            ->withMethod('OPTIONS');
    }

    private function createStackedApp(array $options = []): CorsMiddleware
    {
        $passedOptions = array_merge(
            [
                'allowedHeaders' => ['x-allowed-header', 'x-other-allowed-header'],
                'allowedMethods' => ['delete', 'get', 'post', 'put'],
                'allowedOrigins' => ['http://localhost'],
                'exposedHeaders' => false,
                'maxAge' => false,
                'supportsCredentials' => false,
            ],
            $options
        );

        return new CorsMiddleware(new CorsService($passedOptions));
    }

    private function getRequestHandler(array $responseHeaders): RequestHandlerInterface
    {
        return new class ($responseHeaders) implements RequestHandlerInterface {
            private array $responseHeaders;

            public function __construct(array $responseHeaders)
            {
                $this->responseHeaders = $responseHeaders;
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new TextResponse('', 200, $this->responseHeaders);
            }
        };
    }
}
