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
class ControllerApiSistema extends ControllerApiBase {

    public function getSistema(Request $request, Response $response, array $args) {
        $sSql = "SELECT siscodigo, sisnome, sisativo FROM sistema ORDER BY siscodigo";
        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }
}