<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Chamada da api Sistema
 *
 * User: Gelvazio Camargo
 * Date: 10/12/2020
 * Time: 17:40
 */
require_once("ControllerApiBase.php");
class ControllerApiImagem extends ControllerApiBase {

    public function getImagem(Request $request, Response $response, array $args) {
        $aDados = array("imagem" => "https://cdn.pixabay.com/photo/2020/02/06/20/01/university-library-4825366_960_720.jpg");
        return $response->withJson($aDados, 200);
    }
}