<?php

$request_uri = $_SERVER['REQUEST_URI'];

// echo "request_uri: " . $request_uri;

// require_once ("lib/slim/autoload.php");
// require_once("vendor/autoload.php");

require_once ("../vendor/autoload.php");

//if($request_uri == "/apiphp/api/"){
//} else {
//    require_once ("vendor/autoload.php");
//}

header("Access-Control-Allow-Origin:*");
header('Access-Control-Allow-Credentials: false');
header('Access-Control-Max-Age: 86400');
date_default_timezone_set('America/Maceio');

require_once('core/Utils.php');

use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

require_once("controllers/ControllerApiBase.php");
require_once("controllers/ControllerApiPessoa.php");
require_once("controllers/ControllerApiMenu.php");

require_once("controllers/ControllerApiSistema.php");
require_once("controllers/ControllerApiUsuario.php");
require_once("controllers/ControllerApiProduto.php");
require_once("controllers/ControllerApiImagem.php");
require_once("controllers/ControllerApiConsultaPadrao.php");
require_once("controllers/ControllerApiContato.php");
require_once("controllers/ControllerApiDocumento.php");

require_once("core/HttpStatusCodes.php");

class Routes {

    public function __construct() {
        $this->runApp();
    }

    /**
     * Executa o app para realizar a chamada de rotas
     *
     * @throws Throwable
     */
    protected function runApp() {
        $app = new \Slim\App($this->getConfigurationContainer());

        $c = $app->getContainer();
        $c['notAllowedHandler'] = function ($c) {
            return function ($request, $response, $methods) use ($c) {
                return $response->withJSON(array(
                    "message" => 'Method must be one of: ' . implode(', ', $methods)
                ), 405);
            };
        };

        $app->get('/', ControllerApiBase::class . ':callInfoApi');

        // adicionando cors
        $app->add(function ($req, $res, $next) {
            $response = $next($req, $res);
            return $response
                ->withHeader('Access-Control-Allow-Origin', '*')
                ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
                ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
        });

        // Agrupando rotas para adicionar o middleware em todas as rotas de uma só vez
        $app->group('', function () use ($app) {

            $app->get('/ping', function (Request $request, Response $response, array $args) {
                $data = array("Info:" => date("Y-m-d H:i:s"),
                              "status" =>HttpStatusCodes::HTTP_OK);
                return $response->withStatus(HttpStatusCodes::HTTP_OK)->withJson($data, HttpStatusCodes::HTTP_OK);
            });

            // Autenticação
            $app->get('/usuario', ControllerApiUsuario::class . ':getUsuario');
            $app->post('/login', ControllerApiUsuario::class . ':auth');

            // Sistemas
            $app->get('/sistema', ControllerApiSistema::class . ':getSistema');

            // Menus
            $app->get('/allmenu', ControllerApiMenu::class . ':getAllMenu');
            $app->get('/menu/{siscodigo}', ControllerApiMenu::class . ':getMenu');

            // Cadastros
            $app->get('/pessoa', ControllerApiPessoa::class . ':getPessoa');
            $app->get('/produto', ControllerApiProduto::class . ':getProduto');

            // Produto
            $app->get('/produto/index', ControllerApiProduto::class . ':index');
            $app->get('/produto/create', ControllerApiProduto::class . ':index');
            $app->get('/produto/update', ControllerApiProduto::class . ':index');
            $app->get('/produto/delete', ControllerApiProduto::class . ':index');

            // Contatos
            $app->get('/listaContatos', ControllerApiContato::class . ':listaContatos');
            $app->post('/criaContato', ControllerApiContato::class . ':criaContato');
            $app->post('/atualizaContato', ControllerApiContato::class . ':atualizaContato');
            $app->post('/deletaContato', ControllerApiContato::class . ':deletaContato');

            // Documentos
            $app->get('/listaDocumentos', ControllerApiDocumento::class . ':getDocumentos');
            $app->post('/assinaDocumento', ControllerApiDocumento::class . ':assinaDocumento');

            // Consultas
            $app->get('/consulta/{siscodigo}/{mencodigo}', ControllerApiConsultaPadrao::class . ':getConsultaPadrao');

            // Imagens
            $app->get('/imagem', ControllerApiImagem::class . ':getImagem');
        })->add($this->getMiddlewares());

        $app->run();
    }

    /**
     * Retorna a configuração das rotas
     *
     * @return \Slim\Container
     */
    private function getConfigurationContainer() {
        // Configuração de erros
        $configuration = [
            'settings' => [
                'displayErrorDetails' => true,
            ],
        ];
        $configurationContainer = new \Slim\Container($configuration);

        return $configurationContainer;
    }

    /**
     * Valida se o token é valido
     *
     * @param $token
     * @return bool
     */
    public static function isValidToken($token) {
        $conexao = Utils::getConexao();
        $qrToken = pg_query_params($conexao, "select usuario.usucodigo,
                                                     usuario.usulogin,
                                                     usuario.usutoken
                                                from usuario
                                               where usuario.usutoken = $1
                                                 and coalesce(usuario.usuativo, 0) = 1", array($token));
        if ($rsToken = pg_fetch_assoc($qrToken)) {
            return true;
        }
        return false;
    }

    /**
     * Retorna os midlewares de validação de rotas
     *
     * @return Closure
     */
    private function getMiddlewares() {
        // Middlewares
        $Middlware = function (Request $request, Response $response, $next) {
            if (!Utils::isServidorProducao()) {
                $response = $next($request, $response);
                return $response;
            }

            // Valida as requisições
            if (!Utils::checkRateLimit("API", Utils::getRemoteIP())) {
                $data = array("message" => "Excesso de chamadas");
                return $response->withJson($data, 429);
            }

            $headers = $request->getHeaders();
            $token = $headers["HTTP_X_API_KEY"][0];
            if (trim($token) == "") {
                $data = array("message" => "Acesso inválido - TOKEN - Envio:" . $token);
                return $response->withJson($data, 401);
            }

            $headers = $request->getHeaders();
            $token_api = $headers["HTTP_X_API_TOKEN"][0];
            if (trim($token_api) == "") {
                $data = array("message" => "Acesso inválido - TOKEN-API VAZIO!Token:" . $token_api);
                return $response->withJson($data, 401);
            }

            if ($token_api != self::getTokenApi($headers)) {
                $data = array("message" => "Acesso inválido - TOKEN-API NAO CONFERE!Envio:$token_api");
                return $response->withJson($data, 401);
            }

            // Valida as requisições
//            if (!Utils::checkRateLimit("API", $token)) {
//                $data = array("message" => "Excesso de chamadas");
//                return $response->withJson($data, 429);
//            }

            // Verifica se esse token é valido
//            if (!Routes::isValidToken($token)) {
//                $data = array("message" => "Token inválido");
//                return $response->withJson($data, 401);
//            }

            // codigo de validação de dados do usuario
            $response = $next($request, $response);

            return $response;
        };

        return $Middlware;
    }

    private static function getTokenApi($headers) {
        if (Utils::isServidorProducao()) {
            $token_api = $headers["HTTP_X_API_TOKEN"][0];
            // Frase encriptada
            $token_api_backend = 'BE406D16ABFB8AB03A6AC07C25EBFA9E0D05DB778E0E679F214A13180530D46E1E62D206D4DF7FF8397B18DEFBE3847334809E314AAD2607E15DE7F9597CC990';
            if ($token_api == $token_api_backend) {
                return true;
            }
        }
        return true;
    }

}

$routes = new Routes();
